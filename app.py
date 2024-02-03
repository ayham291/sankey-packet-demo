import time
from flask import Flask, jsonify, render_template
from scapy.all import sniff, IP, TCP
from threading import Thread
import json
import os
from flask_cors import CORS



app = Flask(__name__)
CORS(app)
packets_info = []  # Store packet data

def process_packet(packet):
    # Extract packet data
    if IP in packet and TCP in packet:
        tcp_flags = packet[TCP].flags
        if 'S' in tcp_flags and 'A' not in tcp_flags:
            packet_data = {
                "src": packet[IP].src,
                "dst": packet[IP].dst,
                "proto": packet[IP].proto,
                "len": len(packet)
            }
            packets_info.append(packet_data)
            # print(packet_data)
            # print(packet)

def capture_packets():
    # get the network name from stdin and store it in a variable
    net_interface = os.popen('getDockerNetwork nginx-stream-tls-example_default').read().strip()
    print(f'Capturing packets on {net_interface}')

    # Capture packets
    t = sniff(iface=net_interface, count=1500, prn=process_packet)
    print(t.summary())
    print('Packet capture stopped')

def reset_packet_data():
    # Reset packet data every 30 seconds
    while True:
        global packets_info
        packets_info = []
        time.sleep(60)
        print('Packet data reset')

@app.route('/get_packet_data', methods=['GET'])
def get_packet_data():
    global packets_info
    data = json.dumps(packets_info)  # Convert packet data to JSON
    return jsonify(data)

@app.route('/')
def index():
    return render_template('index.html')

if __name__ == '__main__':
    Thread(target=capture_packets).start()  # Start packet capture in a separate thread
    # Reset packet data every 30 seconds
    # Thread(target=reset_packet_data).start()
    app.run(host='0.0.0.0', port=5000)
