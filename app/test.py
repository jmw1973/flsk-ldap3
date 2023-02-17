import yaml

def getEzmeralSourceData():
  # Open the file and load the file
  with open('ezmeral.yaml') as f:
    data = yaml.safe_load(f)
  return data

def print_values():
  data = getEzmeralSourceData()
  #print(data)

  print(data['environment']['Tenant']['pit1']['cpu'])

  for Tenant, values in data['environment']['Tenant'].items():
    print(Tenant)
    print(values)
    print(data['environment']['Tenant'][Tenant]['cpu'])
    for group, values in values['Groups'].items():
      print(group) # we have the group
      for user in values['Users']:
        print(user)  

    
   
def update_yaml_file(yamlfile, header, dict_data):
  with open(yamlfile,'r') as yamlfile:
    current_yaml = yaml.safe_load(yamlfile)
    current_yaml['environment']['Tenant'][header]['Groups'][header+'_users']['Users'].append(dict_data)
    #return current_yaml
  if current_yaml:
    with open(yamlfile.name, 'w') as f:
       print(current_yaml)
       yaml.safe_dump(current_yaml, f)
       return "201"

updateyamlfile = update_yaml_file('ezmeral.yaml', 'tg3', 'myshinynewuser2')
print(updateyamlfile)
#print_values()
