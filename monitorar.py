import os
import nmap
from scapy.all import sniff, IP
import subprocess

# Função para monitorar a rede WiFi e listar dispositivos conectados
def monitor_wifi():
    nm = nmap.PortScanner()
    network = input("Insira o intervalo de IPs da sua rede (exemplo: 192.168.0.1/24): ")
    nm.scan(hosts=network, arguments='-sn')

    devices = []
    for host in nm.all_hosts():
        if 'mac' in nm[host]['addresses']:
            devices.append({
                'IP': host,
                'MAC': nm[host]['addresses']['mac'],
                'Vendor': nm[host]['vendor']
            })
    return devices

# Função para capturar pacotes de um dispositivo específico
def packet_monitor(device_ip):
    def packet_callback(packet):
        if IP in packet:
            if packet[IP].src == device_ip:
                print(f"Pacote enviado por {device_ip} (Upload)")
            elif packet[IP].dst == device_ip:
                print(f"Pacote recebido por {device_ip} (Download)")

    sniff(filter=f"ip host {device_ip}", prn=packet_callback)

# Listar dispositivos conectados e monitorar pacotes de um dispositivo
def main():
    print("Monitorando a rede...")
    devices = monitor_wifi()

    print("Dispositivos conectados:")
    for i, device in enumerate(devices):
        print(f"{i+1}. IP: {device['IP']} | MAC: {device['MAC']}")

    selected_device = int(input("Selecione o dispositivo que deseja monitorar (número): ")) - 1
    device_ip = devices[selected_device]['IP']

    print(f"Monitorando pacotes de {device_ip}...")
    packet_monitor(device_ip)

if __name__ == "__main__":
    main()