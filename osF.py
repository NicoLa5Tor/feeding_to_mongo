import os,json
class Os_Functions:
    def __init__(self):
        self.folder = os.path.join(os.getcwd(),'db')
    def data_softwares(self):
        with open('data.json','r') as d:
            data_return = json.load(d)
            return data_return['documents']    
    def data_database(self,name):
        with open(name,'r') as d:
            data_return = json.load(d)
            return data_return
    def return_list(self):
        list_comp = [arch for arch in os.listdir(self.folder) if arch.endswith('.json')]
        print(list_comp)
        

    
