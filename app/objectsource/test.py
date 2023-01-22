import yaml
from yaml.loader import SafeLoader

# Open the file and load the file
with open('ezmeral.yaml') as f:
  data = yaml.safe_load(f)

def print_values(data):
  for key, value in data["environment"].items():
    print(key)
    for key, value in value.items():
      print(key) # we have the group
      for user in value:
        print(user) # we have the user


print_values(data)
