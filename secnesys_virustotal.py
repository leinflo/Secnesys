################################################################################################################################################################################################################
################################################################################################################################################################################################################
################################################################################################################################################################################################################
######################### SCRIPT PARA VALIDAR IOCS CON LA API DE VIRUSTOTAL 
######################### SECNESYS MDR/SOC V1
######################### FECHA: 31/37/2022
################################################################################################################################################################################################################
################################################################################################################################################################################################################
################################################################################################################################################################################################################

import argparse
from datetime import datetime
from mailbox import NoSuchMailboxError
import vt
import csv
import json

def main():

  parser = argparse.ArgumentParser(
      description='Virus total API busqueda de IOCs')

  parser.add_argument('--lista',
      type=str,
      required=False,
      help='archivo CSV con los IOCs a validar, primer columna es tipo, segunda columna el valor a buscar ejemplo: url,https://algo.com; regresa un archivo csv con una columna adicional de cuantas veces lo han catalogado como malicioso')
      
  parser.add_argument('--archivo',
      type=str,
      required=False,
      help="artefacto tipo archivo a escanear requiere de la ruta absoluta del archivo con doble backslash C:\\\\ruta\\\\del\\\\archivo")

  parser.add_argument('--url',
      type=str,
      required=False,
      help="Escanear URL en busqueda de malware")

  parser.add_argument('--dominio',
      type=str,
      required=False,
      help="revisar la reputación de un dominio en VirusTotal")

  parser.add_argument('--ip',
      type=str,
      required=False,
      help="revisar la reputación de una IP en VirusTotal")
  
  parser.add_argument('--hash',
      type=str,
      required=False,
      help="revisar la reputación de un archivo con su valor sha256, sha1 o MD5")

  args = parser.parse_args()
  ########################################################################################################
  #######################         Configuración de la API de VirusTotal          #########################
  ########################################################################################################

  api_vt = '9186a2fc4ec938c7f9ba0173f584905837ff0326931c4bd3981927a987baf5b0'
  client = vt.Client(api_vt)

########################################################################################################
########################################################################################################

  ##### busqueda de Hash####
  if args.hash:
    print(f"{args.hash}")
    #with vt.Client(api_vt) as client:
    analisis = client.scan_file(archivo_escaneado,wait_for_completion=True)
    resultado = client.get_object("/files/{}",analisis.hash)
    print(resultado.stats)

##### publicar y analizar un archivo####
  if args.archivo:
    with open(args.archivo,"rb") as archivo_escaneado:
        print(f"{args.archivo}")
        analisis = client.scan_file(archivo_escaneado,wait_for_completion=True)
        resultado = client.get_object("/analyses/{}",analisis.id)
        print(resultado.stats)

##### busqueda de URLS####
  if args.url:
    print(f"{args.url}")
    analisis = client.scan_url(args.url,wait_for_completion=True)
    resultado = client.get_object("/analyses/{}",analisis.id)
    url_id = vt.url_id(args.url)
    url = client.get_object("/urls/{}",url_id)
    url.last_analysis_stats
    print(url.last_analysis_stats)

##### busqueda de dominios####
  if args.dominio:
    print(args.dominio)
    resultado = client.get_object("/domains/{}",args.dominio)
    print(resultado.last_analysis_stats)

##### busqueda de IPs####
  if args.ip:
    print(args.ip)
    resultado = client.get_object("/ip_addresses/{}",args.ip)
    print(resultado.last_analysis_stats)


#####Busqueda Masiva de IOCs####
  if args.lista:
    with open(args.lista) as csv_file:
        print(f"{args.lista}")
        archivo_csv = csv.reader(csv_file, delimiter=',')
        fecha = datetime.now()
        nombre='resultado_'+str(fecha.day)+'_'+str(fecha.month)+'_'+str(fecha.year)+'.csv'
        salida = open(nombre,'w',newline='',encoding='utf-8')
        esc = csv.writer(salida)
        cabecera = ['Tipo','Indicador','malicioso']
        esc.writerow(cabecera)
        contador_linea = 0
        for fila in archivo_csv:
            if contador_linea == 0:
                print(f'La primer columna debe ser el tipo, la segunda el valor')
                contador_linea +=1
            else:
                if {fila[0]}=='url':
                    url_id = vt.url_id(fila[1])
                    url = client.get_object("/urls/{}",url_id)
                    print(fila[1])
                    res = url.last_analysis_stats
                    malicioso = res['malicious']
                    datos=[fila[0],fila[1],malicioso]
                    esc.writerow(datos)
                    print(datos)

                elif {fila[0]}=='hash':
                    file = client.get_object('/files/{}',fila[1])
                    print(fila[1])
                    res = file.last_analysis_stats
                    malicioso = res['malicious']
                    datos=[fila[0],fila[1],malicioso]
                    esc.writerow(datos)
                    print(datos)

                elif {fila[0]=='ip'}:
                    dir_ip = client.get_object('/ip_addresses/{}',fila[1])
                    print(fila[1])
                    res = dir_ip.last_analysis_stats
                    malicioso = res['malicious']
                    datos=[fila[0],fila[1],malicioso]
                    esc.writerow(datos)
                    print(datos)

                elif {fila[0]=='dominio'}:
                    dominio = client.get_object('/domains/{}',fila[1])
                    print(fila[1])
                    res = dominio.last_analysis_stats
                    malicioso = res['malicious']
                    datos=[fila[0],fila[1],malicioso]
                    print(datos)
                    esc.writerow(datos)

                else:
                    print('el tipo {fila[0]} no es posible buscarlo')

        print('hubo {contadorlinea} IOCs')
        salida.close()
  client.close()
if __name__ == '__main__':
  main()
