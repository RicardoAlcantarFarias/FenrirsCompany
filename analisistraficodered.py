from scapy.all import sniff, IP, TCP
import threading

# Variable global para controlar si se debe cancelar el análisis
cancel_analysis = False

def analyze_packet(packet):
    if IP in packet and TCP in packet:
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst
        src_port = packet[TCP].sport
        dst_port = packet[TCP].dport
        
        # Detectar actividad sospechosa
        if packet[TCP].flags == 0x12:  # SYN-ACK
            print(f"Posible escaneo de puertos desde {src_ip}:{src_port} hacia {dst_ip}:{dst_port}")
        elif packet[TCP].flags == 0x02:  # SYN
            print(f"Posible intento de conexión desde {src_ip}:{src_port} hacia {dst_ip}:{dst_port}")
        elif packet[TCP].flags == 0x05:  # RST-ACK
            print(f"Posible escaneo de puertos cerrados desde {src_ip}:{src_port} hacia {dst_ip}:{dst_port}")

def start_analysis():
    global cancel_analysis
    # Configurar el filtro para capturar solo paquetes TCP
    sniff(filter="tcp", prn=analyze_packet, store=0, stop_filter=lambda x: cancel_analysis, timeout=1)

def main():
    global cancel_analysis
    try:
        # Crear un hilo de subproceso para el análisis
        analysis_thread = threading.Thread(target=start_analysis)
        analysis_thread.start()

        # Esperar hasta que el usuario cancele el análisis
        input("Presione Enter para cancelar el análisis...")
        cancel_analysis = True
        analysis_thread.join()
    except KeyboardInterrupt:
        cancel_analysis = True
        print("\nAnálisis cancelado por el usuario.")

if __name__ == "__main__":
    main()
