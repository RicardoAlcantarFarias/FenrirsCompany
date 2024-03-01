import socket
import requests
import subprocess
import platform

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
