import requests 
import time,json
from osF import Os_Functions
import threading
from insformation_machines import Machines_Info

url = 'https://mongoatlas-crxv.onrender.com/'

obj_os = Os_Functions()
obj_db = Machines_Info(url=url)
global vulns_per_soft,name_soft
def search_vulnerabilities_by_keyword(keyword):  
    api_key = 'd2631d16-0495-472d-bf43-4290b2027b19' 
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
def add_db(dt,id):
        uril = f'{url}add_item' 
     #   id = f"VulnsPerMachines_{cont}"
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
    
               
#procesos con base de datos
def concat_vulnerabilities_per_machin():
    machinas = {}
    mas_menos = {}
    machin_top = {}
    total_vulns = 0
    machin_mas , machin_menos = 0,100000000000
    name_mas , name_menos = '',''
    #guscamos todos los datos
    for i in range(17):
         if i > 0:
            id = f'VulnsPerMachines_{i}'
            print(id)
            get_item = obj_db.search_db(id=id)
            name_machine, cont_vul = cont_vulns(item=get_item['response']['item'])
            total_vulns += cont_vul
            machinas[id] =  cont_vul
    #con el sort organizamos los datos del dicchiario de mayor a menor 
    #dejando el reverse en verdadero
    diccionario_ordenado = dict(sorted(machinas.items(), key=lambda item: item[1], reverse=True))
    #print(json.dumps(diccionario_ordenado,indent=2))
    for name_machin,cant_vulns in machinas.items():
         if machin_mas < cant_vulns:
              machin_mas = cant_vulns
              name_mas = name_machin
         if machin_menos > cant_vulns:
              machin_menos = cant_vulns
              name_menos = name_machin
    #print(f'La menos vulnerable es: {name_menos} y la mas es {name_mas} ')
    ym = obj_db.search_db(id=name_menos)
    yma = obj_db.search_db(id=name_mas)
    
    mas_menos ['menos_vuln'] = list(yma['response']['item'].keys())[0]
    mas_menos ['mas_vuln'] = list(ym['response']['item'].keys())[0]
         
    for ord_name, ord_item in list(diccionario_ordenado.items())[:10]:
        awaitAnalisis = 0
        medium = 0
        high = 0
        critical = 0
        low = 0
        none = 0
        total = 0
        dat_objet = obj_db.search_db(id=ord_name)
        data_item = dat_objet['response']['item']
        name_m = ''
        for name,itm in data_item.items():
          name_m = name
          #print(f"El itm es: {itm}")
          for llave,ite in itm.items():
             if  ite != 'No vulnerable':
                for item in ite['Vulns']:              
             
                    print('empieza la concatenacion el item')
                  #  print(item)
                    if len(item['cve']['metrics']) < 1:
                        awaitAnalisis += 1
                    else:
                        if 'cvssMetricV31' in item['cve']['metrics']:
                            i = item['cve']['metrics']['cvssMetricV31'][0]['cvssData']['baseSeverity']
                        elif 'cvssMetricV30' in item['cve']['metrics'] :
                            i = item['cve']['metrics']['cvssMetricV30'][0]['cvssData']['baseSeverity']
                        elif 'cvssMetricV2' in item['cve']['metrics']:
                            if 'baseSeverity' in item['cve']['metrics']['cvssMetricV2'][0]:
                                i = item['cve']['metrics']['cvssMetricV2'][0]['baseSeverity']
                            else:
                                i = item['cve']['metrics']['cvssMetricV2'][0]['cvssData']['baseSeverity']
                #     print(f'el item es {i}')
                        if i == 'MEDIUM':
                            medium += 1
                        elif i == 'HIGH':
                            high += 1
                        elif i == 'CRITICAL':
                            critical += 1
                        elif i == 'LOW':
                            low += 1
                        elif i == 'NONE':
                            none += 1
                    total += 1
        machin_top[name_m] = {
             'None' : none,
             'Low' : low,
             'Medium' : medium,
             'High' : high,
             'Critical' : critical,
             'AwaitAnalisis' : awaitAnalisis,
             'Total' : total,
        }
    return machin_top,mas_menos,total_vulns

         
         

         
        
         
     
    
def cont_vulns(item):
     nam = ''
     cont = 0
     for name_machin,it in item.items():
          print(name_machin)
          nam = name_machin
          for key,val in it.items():
               if val != 'No vulnerable':
                    cont += len(val['Vulns'])
                         

     return nam,cont
                
#Ejecucion e eprocesos de bases de datos
#get_item = obj_db.search_db(id=f'VulnsPerMachines_3')
                    
datos,order,vulns_total =  concat_vulnerabilities_per_machin()
retunr_data = {
    "Top10_Machinas": datos,
    "Menos_Mas" : order,
    "Total_Vulns" : vulns_total

}
add_db(id='Info_Machines',dt=retunr_data)
print(json.dumps(datos,indent=2))
          

#lectura y guardado de todos las masquina sy sus softwares
#concat_dictionary(start=10)
#guardado de top de vulnerabilidades   
""" 
vulnerabilities = [
    {"name": "CVE-2021-34527", "severity": 9.8, "description": "Vulnerability in Windows Print Spooler Components."},
    {"name": "CVE-2021-44228", "severity": 10.0, "description": "Log4Shell vulnerability affecting Apache Log4j2."},
    {"name": "CVE-2021-30860", "severity": 9.7, "description": "Apple iOS and macOS zero-click vulnerability."},
    {"name": "CVE-2021-4034", "severity": 9.8, "description": "PwnKit: Local Privilege Escalation vulnerability in Polkit."},
    {"name": "CVE-2021-21972", "severity": 9.8, "description": "Remote code execution vulnerability in VMware vSphere Client."},
    {"name": "CVE-2021-26084", "severity": 9.8, "description": "Confluence Server Webwork OGNL injection."},
    {"name": "CVE-2021-44228", "severity": 10.0, "description": "Remote code execution in Apache Log4j2."},
    {"name": "CVE-2022-2184", "severity": 9.8, "description": "Critical SQL injection vulnerability."},
    {"name": "CVE-2022-30190", "severity": 9.8, "description": "Microsoft Support Diagnostic Tool Vulnerability."},
    {"name": "CVE-2022-22965", "severity": 9.8, "description": "Spring4Shell vulnerability in Spring Framework."}
]
add_db(cont=1,dt=vulnerabilities)     
     """
#print(json.dumps(dictionaty,indent=2))



