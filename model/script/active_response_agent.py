import time
import json
import logging
from elasticsearch import Elasticsearch
import paramiko
from threading import Thread, Lock
from queue import Queue

# --- CẤU HÌNH TRUNG TÂM ---
CONFIG = {
    "ES_HOSTS": ["http://192.168.193.153:9200"],
    "ES_USER": "elastic",
    "ES_PASS": "t2*EXJQ3ykEaGEhrXpuO",
    "ES_INDEX_PATTERN": "filebeat-*",
    "SWITCH_IP": "192.168.193.150",
    "SWITCH_USER": "ad",
    "SWITCH_PASS": "123456",
    "QUERY_TIME_RANGE": "now-30s",
    "LOOP_SLEEP_INTERVAL": 15,
    # === THAY ĐỔI 1: Thêm IP của Server vào Whitelist ===
    "WHITELIST_IPS": ["192.168.192.1", "8.8.8.8", "192.168.57.100", "192.168.57.200"]
}

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

class ActiveResponseAgent:
    def __init__(self, config):
        self.config = config
        self.es_client = Elasticsearch(
            self.config["ES_HOSTS"],
            basic_auth=(self.config["ES_USER"], self.config["ES_PASS"])
        )
        self.blocked_ips = set()
        # === THAY ĐỔI 2: Sử dụng Queue để quản lý các IP cần chặn ===
        self.block_queue = Queue()
        logging.info("Active Response Agent initialized.")

    def block_worker(self):
        """Luồng công nhân (worker) lắng nghe từ hàng đợi và thực hiện chặn."""
        while True:
            src_ip = self.block_queue.get() # Lệnh này sẽ chờ cho đến khi có mục mới trong queue
            if src_ip is None: # Tín hiệu để dừng
                break
            
            # Kiểm tra lại lần nữa trước khi chặn
            if src_ip in self.config["WHITELIST_IPS"] or src_ip in self.blocked_ips:
                continue

            ssh = None
            try:
                logging.info(f"Worker processing IP: {src_ip}")
                ssh = paramiko.SSHClient()
                ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
                ssh.connect(
                    self.config["SWITCH_IP"],
                    username=self.config["SWITCH_USER"],
                    password=self.config["SWITCH_PASS"],
                    timeout=10
                )
                cmd = f"sudo iptables -I FORWARD 1 -s {src_ip} -j DROP"
                stdin, stdout, stderr = ssh.exec_command(cmd)
                error = stderr.read().decode().strip()
                if error:
                    logging.error(f"IPTables error for {src_ip}: {error}")
                else:
                    logging.warning(f"ACTION: Successfully blocked source IP: {src_ip}")
                    self.blocked_ips.add(src_ip)
            except Exception as e:
                logging.error(f"SSH error for {src_ip}: {e}", exc_info=False)
            finally:
                if ssh: ssh.close()
            self.block_queue.task_done()

    def process_alert(self, hit):
        source = hit.get('_source', {})
        src_ip = source.get('source', {}).get('ip') or \
                 source.get('suricata', {}).get('eve', {}).get('src_ip')
        
        if src_ip and src_ip not in self.blocked_ips:
            logging.info(f"Adding IP {src_ip} to block queue.")
            self.block_queue.put(src_ip)

    def run(self):
        # === THAY ĐỔI 3: Khởi động luồng worker ===
        worker_thread = Thread(target=self.block_worker, daemon=True)
        worker_thread.start()
        logging.info("Blocker worker thread started.")
        
        while True:
            try:
                logging.info(f"Querying Elasticsearch for new alerts...")
                query = { "query": { "bool": { "filter": [ {"range": {"@timestamp": {"gte": self.config["QUERY_TIME_RANGE"]}}}, {"term": {"event.kind": "alert"}} ] } }, "size": 500 }
                response = self.es_client.search(index=self.config["ES_INDEX_PATTERN"], body=query)
                
                hits = response.get('hits', {}).get('hits', [])
                if hits:
                    logging.warning(f"Found {len(hits)} new alert(s).")
                    for hit in hits:
                        self.process_alert(hit)
                else:
                    logging.info("No new alerts found.")
            except Exception as e:
                logging.error(f"An error occurred in the main loop: {e}", exc_info=True)
            
            time.sleep(self.config['LOOP_SLEEP_INTERVAL'])

if __name__ == "__main__":
    agent = ActiveResponseAgent(config=CONFIG)
    agent.run()