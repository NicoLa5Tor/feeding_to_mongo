import requests
import json

class Machines_Info:
    def __init__(self,url):
        self.ulr = url
    def search_db(self,id):
        uri = f'{self.ulr}get_item'
        data = {
        'name_db' : 'NicolasJuan',
        'name_collection' : 'Content',
        '_id' : id
        }
        try:
            response = requests.get(url=uri,json=data)
            dat = response.json()
            if response.status_code == 200:
                
                return dat
            else:
                print(f"Error en la consulta status {response.status_code}")
                print(dat)
            
        
        except Exception as e:
            print(f"Excepcion controlada {str(e)}")
