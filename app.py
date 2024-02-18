import time
from flask import Flask, jsonify, render_template
from scapy.all import sniff, IP, TCP, sr1, ICMP

import ipaddress
from threading import Thread
import json
import os
from flask_cors import CORS
from werkzeug.wrappers import response



app = Flask(__name__)
CORS(app)
packets_info = []  # Store packet data
live_hosts = []
net_interface = os.popen("ip -o -f inet addr show | awk '/172.20.0.*\/16/ {print $2}'").read().strip()

def ping_sweep(ips):
    for ip in ips:
        pkt = IP(dst=str(ip))/ICMP()
        resp = sr1(pkt, timeout=1, verbose=False)
        if resp:
            # print(f"{ip} is up")
            # remove duplicates
            if str(ip) not in live_hosts:
                live_hosts.append(str(ip))
        else:
            pass
            # print(f"{ip} is down or not responding")
    return live_hosts

def chunker(seq, size):
    return (seq[pos:pos + size] for pos in range(0, len(seq), size))

def process_packet(packet):
    # Extract packet data
    # if destination ip is not a previous source ip
    if IP in packet and TCP in packet:
        if packet[IP].dst in [packet['src'] for packet in packets_info]:
            return 
        packet_data = {
            "src": packet[IP].src,
            "dst": packet[IP].dst,
            "proto": packet[IP].proto,
            "sport": packet[TCP].sport,
            "dport": packet[TCP].dport,
            "flags": f'{packet[TCP].flags}',
            "len": len(packet),
            # hostnames
            "hostname": os.popen(f'getent hosts {packet[IP].src}').read().strip(),
        }
        packets_info.append(packet_data)
        print(packet_data)
        # print(packet)

def capture_packets():
    # get the network name from stdin and store it in a variable
    print(f'Capturing packets on {net_interface}')

    # Capture packets
    t = sniff(iface=net_interface, count=1500, prn=process_packet)
    # print(t.summary())
    # print('Packet capture stopped')

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

@app.route('/interface', methods=['GET'])
def interface_name():
    return net_interface


@app.route('/')
def index():
    return render_template('index.html')

@app.route('/network')
def network():
    print('Starting ping sweep ' + str(len(threads)))
    if len(threads) > 0:
        for thread in threads:
            thread.join()
        threads.clear()
    live_hosts.clear()
    for ips in chunker(all_ips, 3):
        thread = Thread(target=ping_sweep, args=(ips,))
        thread.start()
        threads.append(thread)
    
    for thread in threads:
        thread.join()

    return render_template('network.html', live_hosts=live_hosts)

if __name__ == '__main__':
    subnet = "192.168.192.0/24"
    threads = []

    all_ips = [ip for ip in ipaddress.IPv4Network(subnet, strict=False)]

    Thread(target=capture_packets).start()  # Start packet capture in a separate thread
    # # Reset packet data
    Thread(target=reset_packet_data).start()
    app.run(host='0.0.0.0', port=5000)

