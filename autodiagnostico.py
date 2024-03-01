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

os.system('cls')


def menu():
    print("\nBienvenido a la Herramienta de Seguridad Fenrir's \n")
    print("Selecciona una opción:")
    print("1.- Analisos de Trafico de red.")
    print("2.- Escaneo de Puertos IP.")
    print("3.- Herramienta de autodiagnostico")
    print("4.- Escaneo de vulnerabilidades de paginas")
    print("5.- Analisis Forense")
    user_input = input("\nQue te gustaría hacer? ")

    if user_input == "1":
        print("Comenzando Analisis de Trafico de red")
        # Replace this comment with your desired functionality for Option 1.
        def analizar_paquete(paquete, cancel_signal):
            if cancel_signal.is_set():
                return

            if paquete.haslayer(scapy.IP):
                ip_origen = paquete[scapy.IP].src
                ip_destino = paquete[scapy.IP].dst
                print(f"IP Origen: {ip_origen}, IP Destino: {ip_destino}")

            if paquete.haslayer(scapy.TCP):
                puerto_origen = paquete[scapy.TCP].sport
                puerto_destino = paquete[scapy.TCP].dport
                print(f"Puerto TCP Origen: {puerto_origen}, Puerto TCP Destino: {puerto_destino}")

            if paquete.haslayer(scapy.UDP):
                puerto_origen = paquete[scapy.UDP].sport
                puerto_destino = paquete[scapy.UDP].dport
                print(f"Puerto UDP Origen: {puerto_origen}, Puerto UDP Destino: {puerto_destino}")

        def sniff_paquetes(cancel_signal):
        # Sniffing de paquetes en la interfaz de red
            scapy.sniff(store=False, prn=lambda x: analizar_paquete(x, cancel_signal))

        def main():
            print('¡Bienvenido al analizador de paquetes con Scapy!')
            print('Presiona Enter para cancelar el análisis.')

            # Crear una señal de cancelación
            cancel_signal = threading.Event()

            # Crear y comenzar el hilo de sniffing
            sniff_thread = threading.Thread(target=sniff_paquetes, args=(cancel_signal,))
            sniff_thread.start()

            # Esperar a que el usuario presione Enter para cancelar
            input()

            # Establecer la señal de cancelación
            cancel_signal.set()

            # Esperar a que el hilo de sniffing termine
            sniff_thread.join()

            print('Análisis de paquetes cancelado.')
        if __name__ == '__main__':
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
            os.system('clear')
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
        target_url = input("Enter target URL: ")
        def analyze_website(url):
            is_fraudulent = False

            # Obtener el contenido
            try:
                response = requests.get(url)
                content = response.text
            except:
                print("\nNo se pudo acceder al sitio web")
                return True
        
            # Analizar la URL
            url_parsed = urlparse(url)
            if not url_parsed.scheme or not url_parsed.netloc:
                print("\nURL inválida")
                is_fraudulent = True

            # Buscar indicadores de fraude
            suspicious_words = ["lotería", "premio", "regalo", "dinero gratis"]
            for word in suspicious_words:
                if word in content:
                    print("Contenido sospechoso detectado")
                    is_fraudulent = True
                    break
            return is_fraudulent
        result = analyze_website(target_url)
        if result:
            print("\nEl sitio parece FRAUDULENTO")
        else:
            print("\nEl sitio parece LEGÍTIMO")
        def fetch_page(url):
            response = requests.get(url)
            return response.text
        def analyze_page(page_content):
            vulnerabilities = []
            # XSS
            xss_patterns = ["<script>alert(1)</script>", "src=j&Tab;a&Tab;v&Tab;asc&NewLine;ript:alert(&apos;XSS&apos;)"]
            for pattern in xss_patterns:
                if re.search(pattern, page_content):
                    vulnerabilities.append("XSS")

            # Shell injection 
            shell_pattern = "El fichero o directorio no existe"
            if shell_pattern in page_content:
                vulnerabilities.append("Inyección de comandos del sistema operativo")
            
            # Directory traversal 
            traversal_pattern = "root:/bin/bash"
            if traversal_pattern in page_content:
                vulnerabilities.append("Recorrido del directorio")

            # Cabeceras inseguras
            headers = requests.get(target_url).headers
            if "X-XSS-Protection" not in headers:
                vulnerabilities.append("Encabezados inseguros")
    
            return vulnerabilities
        page_content = fetch_page(target_url)
        vulnerabilities = analyze_page(page_content) 
        print(f"\nVulnerabilidades encontradas en {target_url}: {vulnerabilities}")
    elif user_input == "5":
        print("Comenzando el Analisis Forense")
        class ForensicTool:
            def __init__(self):
                self.case_id = ''
                self.evidence = []

            def start_case(self):
                self.case_id = input("Ingrese el ID del caso: ")
                self.evidence = [] 
                print(f"Caso inicial con identificación: {self.case_id}") 

            def add_evidence(self, evidence_path):
                if not os.path.exists(evidence_path):
                    print(f"evidencia en {evidence_path} no existe")
                    return
            
                self.evidence.append(evidence_path)
                print(f"Se agregó evidencia en {evidence_path}")

            def analyze_files(self):
                print("Analizando archivos...")
                suspicious_files = []

                for filepath in self.evidence:
                    filename = os.path.basename(filepath)

                    # Check hash against database of known malicious files
                    file_hash = self.generate_hash(filepath)
                    if self.check_malicious(file_hash):
                        print(f"{filename} Identificado como malicioso")
                        suspicious_files.append(filepath)
                     # Check timestamps  
                    t = os.path.getmtime(filepath)
                    filetime = datetime.datetime.fromtimestamp(t)  
                    if self.check_suspicious_time(filetime):
                        print(f"Marca de tiempo sospechosa en {filename}")
                        suspicious_files.append(filepath)
                return suspicious_files    
            def generate_hash(self, filepath):
                hash_md5 = hashlib.md5()
                with open(filepath, "rb") as f:
                    for chunk in iter(lambda: f.read(4096), b""):
                        hash_md5.update(chunk)
                return hash_md5.hexdigest()
            def check_malicious(self, file_hash): 
            # Logic to check hash against database
                return False 
            def check_suspicious_time(self, filetime):
            # Logic to check if timestamp is suspicious
                return False
        if __name__ == "__main__":
            tool = ForensicTool()
            tool.start_case()
            tool.add_evidence('file1.txt')
            tool.add_evidence('malware.exe')
            tool.analyze_files()

def main():
    while True:
        menu()

if __name__ == '__main__':
    main()

