from flask import Flask, render_template
from scapy.all import sniff
from flask_socketio import SocketIO, emit
from scapy.layers.inet import IP
import threading
from datetime import datetime
import socket

app = Flask(__name__)
socketio = SocketIO(app)
packets_info = []


class NetworkMonitor:
    def __init__(self, interface='wlp0s20f3'):
        self.interface = interface

    def packet_handler(self, packet):
        if IP in packet:
            src_ip = packet[IP].src
            dst_ip = packet[IP].dst
            if src_ip == "127.0.0.1" or dst_ip == "127.0.0.1":
                return
            packet_size = len(packet) / 1024
            timestamp = datetime.now().strftime('%d-%m-%Y %H:%M:%S')
            #src_domain = self.resolve_domain(src_ip)
            #dst_domain = self.resolve_domain(dst_ip)
            packet_info = {'timestamp': timestamp, 'src': src_ip, 'dst': dst_ip, 'size': f"{packet_size:.2f}"}
            packets_info.append(packet_info)

            if len(packets_info) > 100:  # Keep only the latest 10 packets
                packets_info.pop(0)

    def resolve_domain(self, ip_address):
        try:
            return socket.gethostbyaddr(ip_address)[0]
        except socket.herror:
            return ip_address

    def start_sniffing(self):
        sniff(iface=self.interface, prn=self.packet_handler, store=False, filter="ip")

    def start(self):
        thread = threading.Thread(target=self.start_sniffing)
        thread.daemon = True
        thread.start()


monitor = NetworkMonitor()
monitor.start()


@app.route('/')
def index():
    return render_template('index.html', packets=packets_info)


@socketio.on('connect', namespace='/test')
def test_connect():
    for packet in packets_info:
        socketio.emit('packet_update', packet, namespace='/test')


def send_updates():
    while True:
        socketio.emit('packet_update', packets_info, namespace='/test')
        socketio.sleep(2) 


socketio.start_background_task(send_updates)

if __name__ == "__main__":
    socketio.run(host='0.0.0.0', port=5000)
