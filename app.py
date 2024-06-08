from flask import Flask, render_template
from flask_socketio import SocketIO
from scapy.all import sniff
import scapy.all as scapy
from scapy.layers.dns import DNS
from scapy.layers.inet import IP
import threading
from datetime import datetime

app = Flask(__name__)
socketio = SocketIO(app)

# Change packets_info to a dictionary
packets_info = {}


class NetworkMonitor:

    def packet_handler(self, packet):
        if IP in packet:
            src_ip = packet[IP].src
            dst_ip = packet[IP].dst

            dst_domen = extract_domain_from_dns(packet)

            # Filter out packets related to local machine to avoid recursive triggers
            if src_ip == "127.0.0.1" or dst_ip == "127.0.0.1" or src_ip == "172.17.0.3" or dst_ip == "172.17.0.3":
                return

            packet_size = len(packet) / 1024  # Convert to KB
            timestamp = datetime.now().strftime('%d-%m-%Y %H:%M:%S')

            # Create a key for aggregation
            key = (timestamp, src_ip, dst_ip)
            if key in packets_info:
                packets_info[key]['size'] += packet_size
                packets_info[key]['size'] = round(packets_info[key]['size'], 2)
            else:
                packets_info[key] = {'timestamp': timestamp, 'src': src_ip, 'dst': dst_ip,
                                     'size': round(packet_size, 2), 'domen': dst_domen}

    def start_sniffing(self):
        scapy.sniff(prn=self.packet_handler, store=False, filter="ip")

    def start(self):
        thread = threading.Thread(target=self.start_sniffing)
        thread.daemon = True
        thread.start()


def extract_domain_from_dns(packet):
    if packet.haslayer(DNS) and packet[DNS].qr == 1:  # Check if the packet is a DNS response
        for i in range(packet[DNS].ancount):
            rdata = packet[DNS].an[i].rdata
            rrname = packet[DNS].an[i].rrname
            if isinstance(rdata, str) and isinstance(rrname, bytes):
                return rrname.decode("utf-8")


monitor = NetworkMonitor()
monitor.start()


@app.route('/')
def index():
    # Convert dictionary to list for rendering
    packets_list = list(packets_info.values())
    return render_template('index.html', packets=packets_list)


@socketio.on('connect', namespace='/test')
def test_connect():
    packets_list = list(packets_info.values())
    socketio.emit('packet_update', packets_list, namespace='/test')


def send_updates():
    while True:
        packets_list = list(packets_info.values())
        socketio.emit('packet_update', packets_list, namespace='/test')
        socketio.sleep(1)


socketio.start_background_task(send_updates)

if __name__ == "__main__":
    socketio.run(app, host='0.0.0.0', port=5001, allow_unsafe_werkzeug=True)
