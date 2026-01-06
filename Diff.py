# !/usr/bin/env python3
"""
diff.py
Enterprise Network Configuration Impact Analyzer (Cisco IOS)

Usage:
    python diff.py configA.txt configB.txt
"""

import json
import os
import sys
import re
import streamlit as st
from difflib import SequenceMatcher

from collections import defaultdict

from openai import OpenAI


# =========================================================
# 1. PARSER (Cisco IOS hierarchical parser)
# =========================================================

def parse_ios_config(file_content):
    """
    Parses Cisco IOS config from a string (file content).
    """
    config = defaultdict(list)
    current_parent = None

    # Handle both string (from text area) and list of bytes (from file upload)
    if isinstance(file_content, str):
        lines = file_content.splitlines()
    else:
        # Assuming file_content is a file-like object opened in text mode or bytes
        # If it's bytes (streamlit uploader), decode it
        lines = file_content.read().decode('utf-8').splitlines()

    for line in lines:
        line = line.rstrip()

        # Ignore comments and separators
        if not line or line.startswith("!"):
            continue

        # Parent command (no indentation)
        if not line.startswith(" "):
            current_parent = line
            config[current_parent] = []
        else:
            # Child command
            if current_parent:
                config[current_parent].append(line.strip())

    return dict(config)


# =========================================================
# 2. DIFF ENGINE (semantic-aware block diff)
# =========================================================

def diff_configs(old_cfg, new_cfg):
    diffs = []
    parents = set(old_cfg.keys()) | set(new_cfg.keys())

    # Identify purely added and removed parents first
    added_parents = [p for p in parents if p in new_cfg and p not in old_cfg]
    removed_parents = [p for p in parents if p in old_cfg and p not in new_cfg]
    common_parents = [p for p in parents if p in old_cfg and p in new_cfg]

    # Heuristic to detect renamed/modified parents
    # We map removed_p -> added_p if they are similar enough
    parent_renames = {}

    # We process copy of lists to modify them
    pending_added = set(added_parents)
    pending_removed = set(removed_parents)

    for rem in removed_parents:
        best_match = None
        best_ratio = 0.0

        for add in list(pending_added):
            # Check for high similarity
            # 1. Start with same word (e.g. "interface", "logging")
            rem_tokens = rem.split()
            add_tokens = add.split()

            if not rem_tokens or not add_tokens:
                continue

            match_score = 0
            if rem_tokens[0] == add_tokens[0]:
                match_score += 0.4  # Bonus for same first word (command)

            ratio = SequenceMatcher(None, rem, add).ratio()
            match_score += (ratio * 0.6)

            if match_score > 0.6 and match_score > best_ratio:
                best_match = add
                best_ratio = match_score

        if best_match:
            parent_renames[rem] = best_match
            pending_added.remove(best_match)
            pending_removed.remove(rem)

    # Process Common Parents
    for parent in common_parents:
        old_cmds = set(old_cfg.get(parent, []))
        new_cmds = set(new_cfg.get(parent, []))

        added = sorted(new_cmds - old_cmds)
        removed = sorted(old_cmds - new_cmds)

        if added or removed:
            diffs.append({
                "parent": parent,
                "added": added,
                "removed": removed
            })

    # Process Renamed/Modified Parents
    for old_p, new_p in parent_renames.items():
        # Treat as a modification of the parent block
        old_cmds = set(old_cfg.get(old_p, []))
        new_cmds = set(new_cfg.get(new_p, []))

        added_cmds = sorted(new_cmds - old_cmds)
        removed_cmds = sorted(old_cmds - new_cmds)

        diffs.append({
            "parent": new_p,
            "modified_parent_from": old_p,  # Indicator of parent modification
            "added": added_cmds,
            "removed": removed_cmds
        })

    # Process Remaining Added Parents
    for parent in pending_added:
        cmds = new_cfg.get(parent, [])
        # If adds a block with commands, those commands are added.
        # But if the parent itself is the command (no children), track it.
        # Original logic:
        # if not new_cmds: added.append(parent)
        # We can just list all children as added.
        # If no children, it's the parent line itself.

        if not cmds:
            # Single line command added
            diffs.append({
                "parent": parent,
                "added": [parent],  # Treat self as added command
                "removed": []
            })
        else:
            diffs.append({
                "parent": parent,
                "added": sorted(cmds),
                "removed": []
            })

    # Process Remaining Removed Parents
    for parent in pending_removed:
        cmds = old_cfg.get(parent, [])
        if not cmds:
            diffs.append({
                "parent": parent,
                "added": [],
                "removed": [parent]
            })
        else:
            diffs.append({
                "parent": parent,
                "added": [],
                "removed": sorted(cmds)
            })

    return diffs


# =========================================================
# 3. SEMANTIC RULE ENGINE (network meaning)
# =========================================================

SEMANTIC_RULES = [
    {
        "match": lambda p, c: p.startswith("interface") and "shutdown" in c,
        "domain": "INTERFACE",
        "impact": "CRITICAL",
        "reason": "Interface will go down"
    },
    {
        "match": lambda p, c: p.startswith("interface") and "ip address" in c,
        "domain": "INTERFACE",
        "impact": "HIGH",
        "reason": "IP addressing change"
    },
    {
        "match": lambda p, c: p.startswith("router bgp") and "remote-as" in c,
        "domain": "BGP",
        "impact": "CRITICAL",
        "reason": "BGP session reset"
    },
    {
        "match": lambda p, c: p.startswith("router bgp") and "neighbor" in c,
        "domain": "BGP",
        "impact": "HIGH",
        "reason": "BGP neighbor behavior change"
    },
    {
        "match": lambda p, c: p.startswith("router ospf"),
        "domain": "OSPF",
        "impact": "HIGH",
        "reason": "OSPF routing change"
    },
    {
        "match": lambda p, c: "ip access-group" in c,
        "domain": "SECURITY",
        "impact": "HIGH",
        "reason": "Traffic filtering change"
    },
    {
        "match": lambda p, c: p.startswith("ip access-list"),
        "domain": "SECURITY",
        "impact": "HIGH",
        "reason": "ACL rule modification"
    },
    {
        "match": lambda p, c: p.startswith("logging"),
        "domain": "MANAGEMENT",
        "impact": "LOW",
        "reason": "Logging behavior change"
    }
]


def semantic_impact(parent, command):
    for rule in SEMANTIC_RULES:
        if rule["match"](parent, command):
            return rule["domain"], rule["impact"], rule["reason"]

    return "GENERAL", "MEDIUM", "Generic configuration change"


# =========================================================
# 4. ROLLBACK GENERATOR
# =========================================================

def generate_rollback(command, change_type):
    if change_type == "ADDED":
        return f"no {command}"
    elif change_type == "REMOVED":
        return command
    return ""


# =========================================================
# 5. IMPACT ENGINE + JSON BUILDER
# =========================================================

IMPACT_SCORE = {
    "CRITICAL": 10,
    "HIGH": 7,
    "MEDIUM": 4,
    "LOW": 1
}


def build_impact_report(diffs):
    changes = []
    summary = defaultdict(int)
    total_risk = 0

    for diff in diffs:
        parent = diff["parent"]

        for cmd in diff["added"]:
            # If the command is the same as parent, it means it's a top-level command
            # We treat the 'command' argument to semantic_impact as the full line for matching
            target_cmd = cmd if cmd != parent else parent

            domain, impact, reason = semantic_impact(parent, target_cmd)
            summary[impact] += 1
            total_risk += IMPACT_SCORE[impact]

            changes.append({
                "parent": parent,
                "command": cmd,
                "change_type": "ADDED",
                "domain": domain,
                "impact": impact,
                "reason": reason,
                "rollback": generate_rollback(cmd, "ADDED")
            })

        for cmd in diff["removed"]:
            target_cmd = cmd if cmd != parent else parent

            domain, impact, reason = semantic_impact(parent, target_cmd)
            summary[impact] += 1
            total_risk += IMPACT_SCORE[impact]

            changes.append({
                "parent": parent,
                "command": cmd,
                "change_type": "REMOVED",
                "domain": domain,
                "impact": impact,
                "reason": reason,
                "rollback": generate_rollback(cmd, "REMOVED")
            })

    risk_level = (
        "CHANGE WINDOW REQUIRED" if total_risk >= 20 else
        "CAUTION" if total_risk >= 10 else
        "LOW RISK"
    )

    return {
        "summary": dict(summary),
        "risk_score": total_risk,
        "risk_level": risk_level,
        "changes": changes
    }


def summarize_diffs(diffs):
    summary = {
        "added": [],
        "removed": [],
        "modified": []
    }

    for diff in diffs:
        parent = diff["parent"]

        for cmd in diff.get("added", []):
            summary["added"].append({
                "parent": parent,
                "command": cmd
            })

        for cmd in diff.get("removed", []):
            summary["removed"].append({
                "parent": parent,
                "command": cmd
            })

        for mod in diff.get("modified", []):
            summary["modified"].append({
                "parent": parent,
                "from": mod["from"],
                "to": mod["to"]
            })

    return summary


client = OpenAI(
    api_key="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"
)


def analyze_diff_with_llm(
        diffs_data,
        vendor="Cisco",
        device_type="Switch/Router",
        os_type="IOS",
        custom_instructions=None
):
    # client = OpenAI(api_key=os.getenv("OPENAI_API_KEY"))

    diff_summary = summarize_diffs(diffs_data)

    # Base instructions (Default Prompt)
    default_instructions = f"""
You are a senior network architect.

Vendor: {vendor}
Device Type: {device_type}
Operating System: {os_type}

Analyze the configuration changes.

You MUST:
1. Determine overall risk
2. Determine risk for ADDED changes
3. Determine risk for REMOVED changes
4. Determine risk for MODIFIED changes
5. Provide short technical descriptions for each risk

Risk levels: LOW, MEDIUM, HIGH, CRITICAL

Return ONLY valid JSON.

### REQUIRED JSON FORMAT:
{{
  "overall_risk": "LOW | MEDIUM | HIGH | CRITICAL",

  "added_risk": {{
    "level": "LOW | MEDIUM | HIGH | CRITICAL",
    "description": "string"
  }},
  "removed_risk": {{
    "level": "LOW | MEDIUM | HIGH | CRITICAL",
    "description": "string"
  }},
  "modified_risk": {{
    "level": "LOW | MEDIUM | HIGH | CRITICAL",
    "description": "string"
  }},

  "changes": [
    {{
      "parent": "string",
      "command": "string",
      "change_type": "ADDED | REMOVED | MODIFIED",
      "impact": "LOW | MEDIUM | HIGH | CRITICAL",
      "domain": "INTERFACE | BGP | OSPF | SECURITY | MANAGEMENT | GENERAL",
      "description": "short explanation"
    }}
  ]
}}
"""

    # Use custom instructions if provided, otherwise default
    if custom_instructions and custom_instructions.strip():
        # If user provides custom instructions, we assume they replace the main instruction block.
        # We will append the data context to it.
        instruction_part = custom_instructions
    else:
        instruction_part = default_instructions

    # Append Data Context
    prompt = f"""
{instruction_part}

### ADDED CHANGES:
{json.dumps(diff_summary["added"], indent=2)}

### REMOVED CHANGES:
{json.dumps(diff_summary["removed"], indent=2)}

### MODIFIED CHANGES:
{json.dumps(diff_summary["modified"], indent=2)}
"""

    response = client.chat.completions.create(
        model="gpt-4o",
        messages=[
            {"role": "system", "content": "Return ONLY valid JSON"},
            {"role": "user", "content": prompt}
        ],
        temperature=0
    )

    raw_output = response.choices[0].message.content

    # 🔎 Debug (enable if needed)
    # print("RAW LLM OUTPUT:\n", raw_output)

    if not raw_output or not raw_output.strip():
        return {
            "error": "Empty response from LLM",
            "raw_output": raw_output
        }

    # ✅ Try direct JSON parse
    try:
        return json.loads(raw_output)
    except json.JSONDecodeError:
        pass

    # 🔧 Fallback: extract JSON block safely
    try:
        json_match = re.search(r"\{.*\}", raw_output, re.DOTALL)
        if json_match:
            return json.loads(json_match.group(0))
    except Exception:
        pass

    # ❌ Final fallback
    return {
        "error": "Invalid JSON returned by LLM",
        "raw_output": raw_output
    }


# =========================================================
# 6. STREAMLIT APP
# =========================================================

def main():
    st.set_page_config(page_title="Network Config Impact Analyzer", layout="wide")

    st.title("Network Configuration Impact Analyzer")
    st.markdown("Upload two Cisco IOS configuration files to compare them and analyze the impact using AI.")

    # Sidebar for settings
    with st.sidebar:
        st.header("Settings")
        vendor = st.selectbox("Vendor", ["Cisco", "Juniper", "Arista"], index=0)
        device_type = st.selectbox("Device Type", ["Switch", "Router", "Firewall"], index=1)
        os_type = st.selectbox("OS Type", ["IOS", "IOS-XE", "NX-OS"], index=0)

        st.divider()
        st.info("Ensure you have set the OpenAI API Key in the code or environment.")

        st.divider()
        with st.expander("Advanced: Custom AI Prompt"):
            custom_prompt = st.text_area(
                "Enter custom instructions for the AI",
                height=300,
                placeholder="Leave empty to use the default prompt.",
                help="This text will replace the default system instructions. The configuration diff data will be appended to your prompt automatically."
            )

    col1, col2 = st.columns(2)

    with col1:
        st.subheader("Old Configuration")
        old_file = st.file_uploader("Upload Old Config", type=["txt", "cfg", "conf"], key="old_file")
        old_text = st.text_area("Or paste Old Config here", height=200, key="old_text")

    with col2:
        st.subheader("New Configuration")
        new_file = st.file_uploader("Upload New Config", type=["txt", "cfg", "conf"], key="new_file")
        new_text = st.text_area("Or paste New Config here", height=200, key="new_text")

    if st.button("Analyze Impact", type="primary"):
        # Determine source for Old Config
        if old_file:
            old_content = old_file
        elif old_text.strip():
            old_content = old_text
        else:
            st.warning("Please provide the Old Configuration.")
            return

        # Determine source for New Config
        if new_file:
            new_content = new_file
        elif new_text.strip():
            new_content = new_text
        else:
            st.warning("Please provide the New Configuration.")
            return

        with st.spinner("Parsing configurations..."):
            try:
                old_cfg = parse_ios_config(old_content)
                new_cfg = parse_ios_config(new_content)
            except Exception as e:
                st.error(f"Error parsing configurations: {e}")
                return

        with st.spinner("Calculating differences..."):
            diffs = diff_configs(old_cfg, new_cfg)

        if not diffs:
            st.success("No configuration differences found! The files are identical (semantically).")
            return

        # Display Diff
        st.subheader("Configuration Differences")
        st.json(diffs, expanded=False)

        # LLM Analysis
        st.divider()
        st.subheader("AI Impact Analysis")
        with st.spinner("Querying LLM for Impact Analysis..."):
            llm_analysis = analyze_diff_with_llm(
                diffs,
                vendor=vendor,
                device_type=device_type,
                os_type=os_type,
                custom_instructions=custom_prompt
            )

        # Display LLM Output
        if "error" in llm_analysis:
            st.error(f"LLM Analysis Failed: {llm_analysis['error']}")
            with st.expander("Show Raw Output"):
                st.text(llm_analysis.get("raw_output", ""))
        else:
            # Overall Risk Badge
            risk = llm_analysis.get("overall_risk", "UNKNOWN")
            color = "green"
            if risk == "MEDIUM": color = "orange"
            if risk in ["HIGH", "CRITICAL"]: color = "red"

            st.markdown(f"### Overall Risk: :{color}[{risk}]")

            # Risk Summary Columns
            r_col1, r_col2, r_col3 = st.columns(3)
            with r_col1:
                st.info(f"**Added Risk**: {llm_analysis.get('added_risk', {}).get('level', 'N/A')}")
                st.caption(llm_analysis.get('added_risk', {}).get('description', ''))
            with r_col2:
                st.warning(f"**Removed Risk**: {llm_analysis.get('removed_risk', {}).get('level', 'N/A')}")
                st.caption(llm_analysis.get('removed_risk', {}).get('description', ''))
            with r_col3:
                st.error(f"**Modified Risk**: {llm_analysis.get('modified_risk', {}).get('level', 'N/A')}")
                st.caption(llm_analysis.get('modified_risk', {}).get('description', ''))

            # Detailed Changes Table
            st.markdown("#### Detailed Impact Assessment")
            changes = llm_analysis.get("changes", [])
            if changes:
                st.dataframe(changes, use_container_width=True)
            else:
                st.write("No specific impact details returned.")


if __name__ == "__main__":
    main()

# class Diff:
#     def post(self, request):
#         config_a = request.FILES['config_a'].read().decode('utf-8')
#         config_b = request.FILES['config_b'].read().decode('utf-8')

#         old_cfg = parse_ios_config(config_a)
#         new_cfg = parse_ios_config(config_b)

#         diffs = diff_configs(old_cfg, new_cfg)

#         report = build_impact_report(diffs)

#         return commonresponse.success(success_messaging.cred_type_success, report)

