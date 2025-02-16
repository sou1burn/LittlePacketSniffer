import os
import time
import argparse
import threading

SERVER_IP = "172.20.69.216"
FTP_SERVER = SERVER_IP
DEFAULT_PORT = 5000

def generate_tcp_traffic(sessions, port):
    print(f"[+] Генерация {sessions} TCP сессий на {SERVER_IP}:{port}")
    for i in range(sessions):
        os.system(f"iperf3 -c {SERVER_IP} -p {port} -t 1")
        time.sleep(1)

def generate_udp_traffic(sessions, port):
    print(f"[+] Генерация {sessions} UDP сессий на {SERVER_IP}:{port}")
    for i in range(sessions):
        print(f"[*] UDP Сессия {i + 1}/{sessions}")
        os.system(f"iperf3 -u -c {SERVER_IP} -p {port} -b 1M -t 1")
        time.sleep(1)

def generate_ftp_traffic(sessions):
    print(f"[+] Генерация {sessions} FTP-сессий с сервером {FTP_SERVER}")
    for i in range(sessions):
        os.system(f"wget --ftp-user=anonymous --ftp-password= ftp://{FTP_SERVER}/example.txt -O /dev/null")
        time.sleep(1)


def main():
    parser = argparse.ArgumentParser(description="Генератор трафика (TCP, UDP, FTP)")
    parser.add_argument("types", nargs="+", choices=["TCP", "UDP", "FTP"],
                        help="Типы трафика (можно указать несколько)")
    parser.add_argument("sessions", type=int, help="Количество генерируемых сессий")
    parser.add_argument("--port", type=int, default=DEFAULT_PORT, help="Сетевой порт клиента (опционально)")

    args = parser.parse_args()

    threads = []

    if "TCP" in args.types:
        t = threading.Thread(target=generate_tcp_traffic, args=(args.sessions, args.port))
        threads.append(t)

    if "UDP" in args.types:
        t = threading.Thread(target=generate_udp_traffic, args=(args.sessions, args.port))
        threads.append(t)

    if "FTP" in args.types:
        t = threading.Thread(target=generate_ftp_traffic, args=(args.sessions,))
        threads.append(t)

    for t in threads:
        t.start()

    for t in threads:
        t.join()


if __name__ == "__main__":
    main()
