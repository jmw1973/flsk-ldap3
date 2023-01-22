import yaml
from yaml.loader import SafeLoader

Open the file and load the file
with open('ezmeral.yaml') as f:
        data = yaml.safe_load(f)
            print(data)
            print (type(data))
            tenants = data.keys()
            print(tenants)

            groups = []
            for tenant in tenants:
                  #print(data[tenant]['group_admins'])
                    group=data[tenant]['group_admins'].keys()
                      groups.append(group)
                      #print(groups)

                      for tenant in tenants:
                            for grouptype in data[tenant].keys():
                                    print(grouptype)
                                        for group in data[tenant][grouptype].keys():
                                                  print(group)
                                                        print(type(group))
                                                              for user in data[tenant][grouptype][group].keys():
                                                                          print(user)
