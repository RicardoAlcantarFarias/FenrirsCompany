import os
import time
import threading
import socket

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
