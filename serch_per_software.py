import requests 
import time,json
from osF import Os_Functions
import threading

obj_os = Os_Functions()

global vulns_per_soft,name_soft
def search_vulnerabilities_by_keyword(keyword):  
    api_key = '45e9ee1d-47f7-4be9-893b-c54feb808265' 
    headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/58.0.3029.110 Safari/537.3',
            'Authorization': f'Bearer {api_key}'  
        }
    time.sleep(4)
    base_url = "https://services.nvd.nist.gov/rest/json/cves/2.0?keywordSearch="
    query_url = f"{base_url}{keyword}"
    try:
        response = requests.get(query_url,headers=headers)
        response.raise_for_status()
      #  print(query_url)
        
        if response.status_code == 403:
             print("Status code 403 haciendo tiempo de espera de 20 segundos")
             time.sleep(20)
        if response.status_code == 200:
            data = response.json()['vulnerabilities']
            print(data)
            return data,True
        else:
            print("Error al consultar la API del NVD")
            return None,False
    except requests.exceptions.HTTPError as http_err:
        if response.status_code == 404:
            print(f'Error 404: El recurso no se encontró en la URL')
            return [],True
        else:
            print(f'HTTP error occurred: {http_err}')
            time.sleep(15)
            search_vulnerabilities_by_keyword(keyword=keyword)
            
def search_vulnerabilities(name_software):
    try:
        print(f"Escaneo del software {name_software}")
      #  print(json.dumps(url,indent=2))
        response,valid = search_vulnerabilities_by_keyword(name_software,)
        if not valid:
            print('Se eccedió el número de consultas, espera por favor, se retomará en un momento')
            time.sleep(3)
            search_vulnerabilities(name_software) 
        print("Software escaneado, se inicia la concatenación de los cve")
       
        
        print("ya concatena")
        return response
    except requests.exceptions.RequestException as e:
        print(f'Error en la solicitud: {e}')


def validate_search(name_soft):
     try:
          data,valid = search_vulnerabilities_by_keyword(keyword=name_soft)
          if valid:
               return data
          time.sleep(8)
          print("retorna None")
          return None
     except Exception as e:
          print(f"hubo una excepcion pero se controlo {e}")
          time.sleep(8)
          validate_search(name_soft=name_soft)
     
def concat_dictionary(start):
     cont = 0
     cont_soft = 0
     cont_machin_yearn = 0
     global vulns_per_soft,name_soft
     data = obj_os.data_softwares()
     for item in data:
          cont_machin_yearn += 1
          print(cont_machin_yearn)
          if cont_machin_yearn > start-1:     
                dictionaty = {}       
                data_soft = item['softwareData']
                hostname = item['hostname']
                print(hostname)
                if hostname is not None:
                    for i in data_soft:
                            name_soft = i['Name']
                          
                            cont_soft += 1
                       # if cont_soft > 85:       
                            if name_soft is not None:
                                time.sleep(1)
                                cont += 1
                                print(cont)
                                while True:
                                     print(f"busca cont_soft {name_soft}")
                                     vulns_per_soft = validate_search(name_soft=name_soft)
                                     if vulns_per_soft is not None:
                                          break
                                     print("busca de nuevo")
                              #  print(f"Retorna {vulns_per_soft} en el while")
                                if hostname not in dictionaty:
                                    dictionaty[hostname] = {}
                                if name_soft not in dictionaty[hostname]:
                                        dictionaty[hostname][name_soft] = {}
                                
                                if len(vulns_per_soft) == 0:
                                    dictionaty[hostname][name_soft] = 'No vulnerable'
                                else: 
                                    dictionaty[hostname][name_soft]['Vulns'] = vulns_per_soft
                
                while True:
                        if add_db(dt=dictionaty,cont=cont_machin_yearn):
                            print(f"machin {hostname} se ha guardado ")
                            break
                time.sleep(15)
def add_db(dt,cont):
        uril = 'https://mongoatlas-crxv.onrender.com/add_item' 
        id = f"VulnsPerMachines_{cont}"
        data = {
                "name_db" : "NicolasJuan",
                "_id" : id,
                "name_collection" : "Content",
                "item" : dt
                }
        try:
            response = requests.post(url=uril,json=data)
            if response.status_code == 201:
                return True
            else:
                return False    
        except Exception as e:
            print(f"Acurrio un error {str(e)}")
            return False
    
               

               
                    
               
          


concat_dictionary(start=4)

         
         

     
#print(json.dumps(dictionaty,indent=2))

