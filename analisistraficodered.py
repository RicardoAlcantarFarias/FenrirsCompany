import scapy.all as scapy
import threading

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

