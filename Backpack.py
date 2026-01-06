class Backpack:
    pass


class Backpack1:
    def __init__(self, name):
        self.name = name


backpack1 = Backpack1("Backpack1")

print(backpack1.name)


class Backpack3:

    def __init__(self, name,items):
        self._name = name
        self.items = items

    def add(self, item):
        self.items.append(item)


    def get_name(self):
        return self._name
    def set_name(self, name):
        self._name = name

    name=property(get_name, set_name)

    def __str__(self):
        return f"{self._name}|{self.items}"


backpack3 = Backpack3("Backpack3",[])
backpack3.add("lunch box")
print(backpack3)
#backpack3._name = "Backpack4"

print(backpack3.name)