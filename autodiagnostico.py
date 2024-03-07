import sys
import scapy.all as scapy
import threading
import socket
import requests
import subprocess
import platform
import os
import time
import threading
import socket
import PySimpleGUI as sg
import requests
import re
from urllib.parse import urlparse
import hashlib
import datetime
import requests

os.system('cls')


def menu():
    print("\nBienvenido a la Herramienta de Seguridad Fenrir's \n")
    print("Selecciona una opción:")
    print("1.- Analisis deteccion de Intrusos")
    print("2.- Escaneo de Puertos IP.")
    print("3.- Herramienta de autodiagnostico")
    print("4.- Escaneo de vulnerabilidades de paginas")
    print("5.- Analisis Forense")
    user_input = input("\nQue te gustaría hacer? ")

    if user_input == "1":
        print("Comenzando Analisis de Trafico de red")
        def get_info(resource, api_key):
            url = 'https://www.virustotal.com/vtapi/v2/url/report'
            params = {'apikey': api_key, 'resource': resource}
            
            if '.' in resource:  # Suponemos que es una URL o un dominio
                url = 'https://www.virustotal.com/vtapi/v2/url/report'
            elif ':' in resource:  # Suponemos que es una dirección IP
                url = 'https://www.virustotal.com/vtapi/v2/ip-address/report'
            else:  # Suponemos que es un hash de archivo
                url = 'https://www.virustotal.com/vtapi/v2/file/report'

            response = requests.get(url, params=params)
            
            # Verificar si la respuesta es vacía
            if response.text:
                try:
                    data = response.json()
                    return data
                except ValueError as e:
                    print(f"Error al decodificar la respuesta JSON: {e}")
                    return None
            else:
                print("La respuesta recibida está vacía.")
                return None

        def main():
            api_key = '85418d0763f67104dda7e4b484a932109ffcb4780fce4eeca9ab09d30927499b'  # Reemplaza 'TU_API_KEY' con tu clave API de VirusTotal
            resource = input("Introduce la URL, dirección IP, dominio o hash de archivo a analizar: ")
            info = get_info(resource, api_key)
            
            if info:
                if 'response_code' in info:
                    if info['response_code'] == 1:
                        print("Información:")
                        if 'url' in info:
                            print(f"Recurso: {info['url']}")
                        elif 'ip_address' in info:
                            print(f"Dirección IP: {info['ip_address']}")
                        elif 'md5' in info:
                            print(f"Hash MD5: {info['md5']}")
                        print(f"Positivos totales: {info['positives']}")
                        print(f"Motor de detección: {info['scan_date']}")
                        print("Resultados:")
                        for engine, result in info['scans'].items():
                            print(f"{engine}: {result['result']}")
                    else:
                        print("El recurso no fue encontrado en la base de datos de VirusTotal.")
                else:
                    print("Error al obtener información.")
            else:
                print("No se pudo obtener información para el recurso especificado.")

        if __name__ == "__main__":
            main()


    elif user_input == "2":
        print("Comenzando Escaneo de Puerto IP")
        # Replace this comment with your desired functionality for Option 2.
        def port_scan(ip, port, cancel_signal):
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(1)

            try:
                s.connect((ip, port))
                if not cancel_signal.is_set():
                    print(f'Puerto {port}: está abierto.')
            except:
                if not cancel_signal.is_set():
                    print(f'Puerto {port}: está cerrado.')
            finally:
                s.close()

        def scan_ports(ip, start_port, end_port, cancel_signal):
            port_range = range(start_port, end_port + 1)

            for port in port_range:
                if cancel_signal.is_set():
                    print('Escaneo cancelado.')
                    return
                port_scan(ip, port, cancel_signal)

        def main():
            os.system('cls')
            print('¡Bienvenido al escáner de puertos!')
            time.sleep(2)

            # Obtener automáticamente la dirección IP del host local
            ip = input('Ingrese la dirección IP para escanear (presiona Enter para usar la dirección local): ')
            ip = ip if ip else socket.gethostbyname(socket.gethostname())

            # Obtener automáticamente el número de puertos del sistema
            start_port = int(input('Ingrese el número de puerto inicial (presiona Enter para usar el puerto 1): ') or 1)
            end_port = int(input('Ingrese el número de puerto final (presiona Enter para usar el puerto 65536): ') or 65536)

            num_threads = os.cpu_count()

            # Crear una señal de cancelación
            cancel_signal = threading.Event()

            thread_list = []

            for i in range(num_threads):
                start_range = start_port + i * (end_port - start_port) // num_threads
                end_range = start_port + (i + 1) * (end_port - start_port) // num_threads

            t = threading.Thread(target=scan_ports, args=(ip, start_range, end_range, cancel_signal))
            thread_list.append(t)
            t.start()

            input('Presiona Enter para cancelar el escaneo...')
            # Establecer la señal de cancelación
            cancel_signal.set()

            for t in thread_list:
                t.join()

            print('Escaneo completo.')
        if __name__ == '__main__':
            main()

    elif user_input == "3":
        print("Comenzando Herramienta de Auto Diagnostico")
        # Replace this comment with your desired functionality for Option 3.
        def verificar_puerto(ip, puerto):
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(1)
                sock.connect((ip, puerto))
                sock.close()
                return True
            except socket.error:
                return False

        def verificar_conexion_internet():
            try:
                response = requests.get("http://www.google.com", timeout=5)
                if response.status_code == 200:
                    return True
            except requests.ConnectionError:
                pass
            return False

        def verificar_firewall():
            sistema_operativo = platform.system()
            if sistema_operativo == "Windows":
                try:
                    subprocess.check_output("netsh advfirewall show all", shell=True)
                    return True
                except subprocess.CalledProcessError:
                    pass
            elif sistema_operativo == "Linux":
                try:
                    subprocess.check_output("iptables -L", shell=True)
                    return True
                except subprocess.CalledProcessError:
                    pass
            return False

        def verificar_parches():
            sistema_operativo = platform.system()
            if sistema_operativo == "Windows":
                try:
                    salida = subprocess.check_output("wmic qfe list brief")
                    return True
                except subprocess.CalledProcessError:
                    return False
            elif sistema_operativo == "Linux":
                try:
                    salida = subprocess.check_output("apt list --upgradable") 
                    return True
                except subprocess.CalledProcessError:   
                    return False
            return False  # Devuelve False si no se puede verificar

        def main():
            print("Herramienta de Auto-Diagnóstico de Ciberseguridad")
            print("-" * 50)

            ip_destino = input("Ingrese la dirección IP para el diagnóstico: ")

            print("\n[1] Verificando conexión a Internet...")
            if verificar_conexion_internet():
                print("    Conexión a Internet: OK")
            else:
                print("    Conexión a Internet: Fallo")

            print("\n[2] Verificando puertos comunes...")
            puertos_comunes = [80, 443, 21, 22, 3389]
            for puerto in puertos_comunes:
                if verificar_puerto(ip_destino, puerto):
                    print(f"    Puerto {puerto}: Abierto")
                else:
                    print(f"    Puerto {puerto}: Cerrado")

            print("\n[3] Verificando configuración del firewall...")
            if verificar_firewall():
                print("    Configuración del firewall: OK")
            else:
                print("    Configuración del firewall: Fallo")
                
            print("\n[4] Verificando parches de sistema operativo...")
            if verificar_parches():
                print(" Parches de sistema operativo: Actualizados") 
            else:
                print(" Parches de sistema operativo: Desactualizados")
            print("\nDiagnóstico completo.")

        if __name__ == "__main__":
            main()
    elif user_input == "4":
        print("Comenzando Escaneo de vunerabilidades de paginas web")
        def scan_website():
            url = input("Ingrese la URL del sitio web a escanear: ")

            try:
                # Enviar una solicitud GET a la URL
                response = requests.get(url)
                response.raise_for_status()  # Lanzar una excepción si la solicitud falla

                # Buscar posibles vulnerabilidades
                check_xss(response.text)
                check_sql_injection(url)
                check_open_redirects(response.text)
                
                # Verificar la reputación del sitio
                if check_site_reputation(url):
                    print("El sitio parece ser legítimo.")
                else:
                    print("El sitio puede ser fraudulento.")

                print(f"Escaneo completado para {url}")
            except requests.exceptions.RequestException as e:
                print(f"Error al escanear {url}: {e}")

        def check_xss(html):
            # Buscar campos de entrada de formulario
            input_fields = ['<input', '<textarea']
            for field in input_fields:
                if field in html:
                    print("Se encontró una posible vulnerabilidad XSS en los campos de entrada. Esto significa que un atacante puede intentar inyectar código malicioso, como scripts, en el sitio web, lo que podría comprometer la seguridad del usuario.")

        def check_sql_injection(url):
            # Enviar una solicitud con una carga útil de inyección SQL
            payload = "' OR '1'='1"
            test_url = f"{url}?id={payload}"
            response = requests.get(test_url)

            # Analizar la respuesta para detectar posibles vulnerabilidades
            if "error" not in response.text.lower():
                print("Se encontró una posible vulnerabilidad de inyección SQL. Esto significa que un atacante puede manipular la consulta SQL enviada al servidor, lo que podría permitir el acceso no autorizado a la base de datos y la manipulación de datos sensibles.")

        def check_open_redirects(html):
            # Buscar redirecciones abiertas
            redirect_params = ['redirect', 'url=']
            for param in redirect_params:
                if param in html:
                    print("Se encontró una posible redirección abierta. Esto significa que un atacante puede manipular los parámetros de la URL para redirigir al usuario a sitios maliciosos, phishing u otros sitios no deseados sin su conocimiento.")
                    
        def check_site_reputation(url):
            # Verificar la reputación del sitio utilizando Google Safe Browsing API
            api_key = "TU_API_KEY"  # Reemplaza esto con tu API key de Google Safe Browsing
            safe_browsing_url = f"https://safebrowsing.googleapis.com/v4/threatMatches:find?key={api_key}"
            payload = {
                "client": {
                    "clientId": "yourcompany",
                    "clientVersion": "1.5.2"
                },
                "threatInfo": {
                    "threatTypes": ["MALWARE", "SOCIAL_ENGINEERING"],
                    "platformTypes": ["ANY_PLATFORM"],
                    "threatEntryTypes": ["URL"],
                    "threatEntries": [
                        {"url": url}
                    ]
                }
            }
            response = requests.post(safe_browsing_url, json=payload)
            if response.status_code == 200:
                data = response.json()
                if 'matches' in data:
                    print("Advertencia: Este sitio ha sido identificado como potencialmente peligroso por Google Safe Browsing.")
                    return False
            return True

        # Ejemplo de uso
        scan_website()
    elif user_input == "5":
        print("Comenzando el Analisis Forense")
        def analyze_file(file_path):
            if os.path.isfile(file_path):
                # Leer el contenido del archivo
                with open(file_path, 'r', encoding='utf-8', errors='ignore') as file:
                    content = file.read()

                # Definir patrones sospechosos
                malicious_patterns = [
                    r'password\s*=\s*[\'""]?([^\'""\s]+)[\'""]?', # Buscar contraseñas
                    r'(ssh|ftp|telnet)\s*:\s*[^\s]+@[^\s]+',  # Buscar credenciales de acceso remoto
                    r'(\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b)',  # Buscar direcciones IP
                    r'(https?|ftp)\s*:\s*[^\s]+',  # Buscar URLs
                    r'exec\s*\([^)]*sh\s+[-|<]',  # Buscar ejecución de shell
                    # Agregar más patrones según sea necesario
                ]

                # Buscar coincidencias con patrones sospechosos
                suspicious_activities = []
                for pattern in malicious_patterns:
                    matches = re.findall(pattern, content)
                    if matches:
                        suspicious_activities.extend(matches)

                return suspicious_activities
            else:
                print(f"No se pudo abrir el archivo: {file_path}")
                return None

        def analyze_directory(directory):
            suspicious_activities = {}
            for root, _, files in os.walk(directory):
                for file in files:
                    file_path = os.path.join(root, file)
                    suspicious_activities[file_path] = analyze_file(file_path)
            return suspicious_activities

        def main():
            path = input("Ingrese la ruta del archivo o directorio para analizar: ")
            if os.path.isfile(path):
                suspicious_activities = analyze_file(path)
                if suspicious_activities:
                    print(f"Se encontraron actividades sospechosas en el archivo: {path}")
                    for activity in suspicious_activities:
                        print(activity)
                else:
                    print(f"No se encontraron actividades sospechosas en el archivo: {path}")
            elif os.path.isdir(path):
                suspicious_activities = analyze_directory(path)
                suspicious_files = [file_path for file_path, activities in suspicious_activities.items() if activities]
                if suspicious_files:
                    print("Se encontraron actividades sospechosas en los siguientes archivos y/o directorios:")
                    for file_path in suspicious_files:
                        print(f"Archivo o directorio: {file_path}")
                        for activity in suspicious_activities[file_path]:
                            print(activity)
                else:
                    print(f"No se encontraron actividades sospechosas en los siguientes archivos y/o directorios: {path}")
            else:
                print("La ruta especificada no es válida.")

        if __name__ == "__main__":
            main()

def main():
    while True:
        menu()

if __name__ == '__main__':
    main()

