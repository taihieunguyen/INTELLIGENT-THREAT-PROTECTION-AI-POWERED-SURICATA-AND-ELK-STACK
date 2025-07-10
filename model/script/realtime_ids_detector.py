import time
import json
import logging
import joblib
import numpy as np
import pandas as pd
from scapy.all import sniff, IP, TCP, UDP
from collections import defaultdict
from threading import Thread, Lock
from datetime import datetime, timezone

# --- Cấu hình (Giữ nguyên) ---
CONFIG = {
    "INTERFACE": "ens34",
    "MODEL_PATH": "rf_ids_optimal_model.joblib",
    "SCALER_PATH": "scaler_optimal.joblib",
    "FEATURES_PATH": "optimal_features.json",
    "LOG_FILE_PATH": "/var/log/ml_ids_alerts.log",
    "FLOW_TIMEOUT": 10,
    "PACKET_THRESHOLD_FOR_ML": 50,
    "PORTSCAN_THRESHOLD": 20,
    "DDOS_PACKET_RATE_THRESHOLD": 200,
    "PROTECTED_HOSTS": ["192.168.57.200"] 
}

class Flow:
    # ... (Lớp Flow giữ nguyên như phiên bản trước) ...
    def __init__(self, flow_id):
        self.flow_id = flow_id; self.packets = []; self.start_time = time.time(); self.last_seen = time.time(); self.flags = defaultdict(int)
    def add_packet(self, packet, direction):
        self.packets.append({'pkt': packet, 'dir': direction}); self.last_seen = time.time()
        if packet.haslayer(TCP):
            flags_str = str(packet[TCP].flags)
            if 'F' in flags_str: self.flags['FIN Flag Count'] += 1
            if 'S' in flags_str: self.flags['SYN Flag Count'] += 1
            if 'R' in flags_str: self.flags['RST Flag Count'] += 1
            if 'P' in flags_str: self.flags['PSH Flag Count'] += 1
            if 'A' in flags_str: self.flags['ACK Flag Count'] += 1
            if 'U' in flags_str: self.flags['URG Flag Count'] += 1
            if 'E' in flags_str: self.flags['ECE Flag Count'] += 1
            if 'C' in flags_str: self.flags['CWE Flag Count'] += 1
    def calculate_features(self, feature_names):
        if len(self.packets) < 2: return None
        feature_dict = {}; fwd_packets = [p['pkt'] for p in self.packets if p['dir'] == 'fwd']; bwd_packets = [p['pkt'] for p in self.packets if p['dir'] == 'bwd']
        feature_dict['Flow Duration'] = (self.last_seen - self.start_time) * 1e6
        first_packet = self.packets[0]['pkt']
        feature_dict['Destination Port'] = first_packet.dport if hasattr(first_packet, 'dport') else 0
        bwd_pkt_lengths = [len(p) for p in bwd_packets]; all_pkt_lengths = [len(p['pkt']) for p in self.packets]
        feature_dict['Bwd Packet Length Max'] = max(bwd_pkt_lengths) if bwd_pkt_lengths else 0; feature_dict['Fwd Packet Length Max'] = max([len(p) for p in fwd_packets]) if fwd_packets else 0
        feature_dict['Average Packet Size'] = np.mean(all_pkt_lengths) if all_pkt_lengths else 0; feature_dict['Bwd Packet Length Min'] = min(bwd_pkt_lengths) if bwd_pkt_lengths else 0
        feature_dict['Min Packet Length'] = min(all_pkt_lengths) if all_pkt_lengths else 0
        init_win_bwd = next((p[TCP].window for p in bwd_packets if p.haslayer(TCP)), 0); feature_dict['Init_Win_bytes_backward'] = init_win_bwd
        init_win_fwd = next((p[TCP].window for p in fwd_packets if p.haslayer(TCP)), 0); feature_dict['Init_Win_bytes_forward'] = init_win_fwd
        duration_sec = self.last_seen - self.start_time; feature_dict['Flow Bytes/s'] = sum(all_pkt_lengths) / duration_sec if duration_sec > 0 else 0
        feature_dict['min_seg_size_forward'] = min([p[IP].ihl * 4 for p in fwd_packets if p.haslayer(IP)]) if any(p.haslayer(IP) for p in fwd_packets) else 0
        feature_dict['Fwd IAT Total'] = sum(np.diff([p.time for p in fwd_packets])) if len(fwd_packets) > 1 else 0
        feature_dict['Bwd IAT Min'] = min(np.diff([p.time for p in bwd_packets])) if len(bwd_packets) > 1 else 0
        timestamps = [p['pkt'].time for p in self.packets]; feature_dict['Idle Min'] = min(np.diff(timestamps)) if len(timestamps) > 1 else 0
        feature_dict['Total Backward Packets'] = len(bwd_packets); feature_dict['Total Fwd Packets'] = len(fwd_packets)
        feature_dict['Total Length of Bwd Packets'] = sum(bwd_pkt_lengths); feature_dict['Total Length of Fwd Packets'] = sum(len(p) for p in fwd_packets)
        feature_dict['Bwd Packet Length Std'] = np.std(bwd_pkt_lengths) if bwd_pkt_lengths else 0; feature_dict['Flow Packets/s'] = len(all_pkt_lengths) / duration_sec if duration_sec > 0 else 0
        feature_dict['Flow IAT Std'] = np.std(np.diff(timestamps)) if len(timestamps) > 1 else 0; feature_dict['Bwd Packet Length Mean'] = np.mean(bwd_pkt_lengths) if bwd_pkt_lengths else 0
        feature_dict['SYN Flag Count'] = self.flags.get('SYN Flag Count', 0); feature_dict['PSH Flag Count'] = self.flags.get('PSH Flag Count', 0)
        feature_dict['ACK Flag Count'] = self.flags.get('ACK Flag Count', 0); feature_dict['URG Flag Count'] = self.flags.get('URG Flag Count', 0)
        feature_dict['CWE Flag Count'] = self.flags.get('CWE Flag Count', 0); feature_dict['ECE Flag Count'] = self.flags.get('ECE Flag Count', 0)
        feature_dict['FIN Flag Count'] = self.flags.get('FIN Flag Count', 0); feature_dict['RST Flag Count'] = self.flags.get('RST Flag Count', 0)
        feature_values = {name: feature_dict.get(name, 0) for name in feature_names}; return pd.DataFrame([feature_values])

class IDSDetector:
    def __init__(self, config):
        self.config = config
        self.model = joblib.load(config["MODEL_PATH"])
        self.scaler = joblib.load(config["SCALER_PATH"])
        with open(config["FEATURES_PATH"], 'r') as f:
            self.feature_names = json.load(f)
        self.flows = {}
        self.ip_packet_count = defaultdict(int)
        self.ip_packet_timestamp = defaultdict(float)
        self.portscan_tracker = defaultdict(lambda: {"ports": set(), "first_seen": time.time()})
        self.lock = Lock()
        logging.basicConfig(format='%(levelname)s:%(name)s:%(message)s', level=logging.DEBUG, handlers=[logging.FileHandler(config["LOG_FILE_PATH"], 'a'), logging.StreamHandler()])
        logging.info("IDS Detector initialized successfully.")

    def _get_flow_key(self, packet):
        if IP in packet and (TCP in packet or UDP in packet):
            ip_pair = tuple(sorted((packet[IP].src, packet[IP].dst)))
            port_pair = tuple(sorted((packet.sport, packet.dport)))
            proto = packet[IP].proto
            return (ip_pair[0], port_pair[0], ip_pair[1], port_pair[1], proto)
        return None

    def _log_alert(self, signature, packet, category="intrusion_detection", metadata=None):
        alert = {
            "@timestamp": datetime.now(timezone.utc).isoformat(),
            "event": {"kind": "alert", "category": category, "type": "network"},
            "source": {"ip": packet[IP].src, "port": packet.sport if packet.haslayer(TCP) or packet.haslayer(UDP) else 0},
            "destination": {"ip": packet[IP].dst, "port": packet.dport if packet.haslayer(TCP) or packet.haslayer(UDP) else 0},
            "network": {"protocol": "tcp" if packet.haslayer(TCP) else "udp"},
            "ids": {"engine": "ML-Hybrid-IDS", "signature": signature}
        }
        if metadata:
            alert['metadata'] = metadata
        logging.warning(json.dumps(alert))

    def check_heuristic_attacks(self, packet):
        dst_ip = packet[IP].dst; src_ip = packet[IP].src; now = time.time()
        if dst_ip in self.config["PROTECTED_HOSTS"]:
            if now - self.ip_packet_timestamp[dst_ip] > 1:
                self.ip_packet_count[dst_ip] = 0; self.ip_packet_timestamp[dst_ip] = now
            self.ip_packet_count[dst_ip] += 1
            if self.ip_packet_count[dst_ip] > self.config["DDOS_PACKET_RATE_THRESHOLD"]:
                self._log_alert(f"Attack Detected: DDoS (Packet Flood)", packet, category="dos"); self.ip_packet_count[dst_ip] = 0; return True
        if packet.haslayer(TCP) and str(packet[TCP].flags) == 'S' and dst_ip in self.config["PROTECTED_HOSTS"]:
            if now - self.portscan_tracker[src_ip]["first_seen"] > 10:
                self.portscan_tracker[src_ip]["ports"].clear(); self.portscan_tracker[src_ip]["first_seen"] = now
            self.portscan_tracker[src_ip]["ports"].add(packet.dport)
            if len(self.portscan_tracker[src_ip]["ports"]) > self.config["PORTSCAN_THRESHOLD"]:
                metadata = {"scanned_ports_count": len(self.portscan_tracker[src_ip]["ports"])}
                self._log_alert(f"Attack Detected: PortScan", packet, category="reconnaissance", metadata=metadata)
                self.portscan_tracker[src_ip]["ports"].clear(); return True
        return False
        
    def _analyze_and_predict(self, flow):
        try:
            # === THÊM LOG DEBUG ===
            logging.info(f"DEBUG: Analyzing flow {flow.flow_id}. Packets in flow: {len(flow.packets)}")
            features_df = flow.calculate_features(self.feature_names)
            if features_df is not None:
                scaled_features = self.scaler.transform(features_df)
                prediction = self.model.predict(scaled_features)
                predicted_class = prediction[0]
                # === THÊM LOG DEBUG ===
                logging.info(f"DEBUG: Model prediction for flow {flow.flow_id} is: {predicted_class}")
                if predicted_class != "BENIGN":
                    packet_for_log = flow.packets[0]['pkt']
                    self._log_alert(f"Attack Detected: {predicted_class} (ML Model)", packet_for_log, metadata={"flow_id": str(flow.flow_id)})
            else:
                # === THÊM LOG DEBUG ===
                logging.info(f"DEBUG: Feature calculation for flow {flow.flow_id} returned None. No prediction made.")
        except Exception as e:
            logging.error(f"Error in _analyze_and_predict: {e}", exc_info=True)

    def process_packet(self, packet):
        try:
            if not packet.haslayer(IP): return
            #if self.check_heuristic_attacks(packet): return
            if not (packet.haslayer(TCP) or packet.haslayer(UDP)): return
            
            flow_key = self._get_flow_key(packet)
            if flow_key:
                with self.lock:
                    flow = self.flows.setdefault(flow_key, Flow(flow_key))
                    direction = 'fwd' if tuple(sorted((packet[IP].src, packet[IP].dst)))[0] == flow_key[0] else 'bwd'
                    flow.add_packet(packet, direction)
                    # === THÊM LOG DEBUG ===
                    logging.info(f"DEBUG: Packet added to flow {flow_key}. Total packets: {len(flow.packets)}")

                    if len(flow.packets) >= self.config["PACKET_THRESHOLD_FOR_ML"]:
                        # === THÊM LOG DEBUG ===
                        logging.info(f"DEBUG: PACKET THRESHOLD of {self.config['PACKET_THRESHOLD_FOR_ML']} MET for flow {flow_key}.")
                        thread = Thread(target=self._analyze_and_predict, args=(self.flows.pop(flow_key),))
                        thread.start()
        except Exception as e:
            logging.error(f"Error in process_packet: {e}", exc_info=True)

    def check_flow_timeouts(self):
        while True:
            time.sleep(self.config["FLOW_TIMEOUT"])
            with self.lock:
                timed_out_keys = [key for key, flow in self.flows.items() if time.time() - flow.last_seen > self.config["FLOW_TIMEOUT"]]
            
            for key in timed_out_keys:
                with self.lock:
                    flow = self.flows.pop(key, None)
                if flow:
                    # === THÊM LOG DEBUG ===
                    logging.info(f"DEBUG: FLOW TIMED OUT for flow {key}.")
                    thread = Thread(target=self._analyze_and_predict, args=(flow,))
                    thread.start()

    def start(self):
        logging.info(f"🚀 Starting Hybrid IDS Detector on interface {self.config['INTERFACE']}...")
        timeout_thread = Thread(target=self.check_flow_timeouts, daemon=True)
        timeout_thread.start()
        sniff(iface=self.config['INTERFACE'], prn=self.process_packet, store=False)

if __name__ == "__main__":
    detector = IDSDetector(config=CONFIG)
    detector.start()