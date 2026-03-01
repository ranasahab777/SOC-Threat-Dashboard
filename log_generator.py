import time
import random

LOG_FILE = "access.log"

NORMAL_IPS = ["192.168.1.50", "10.0.0.5", "172.16.0.12"]
ATTACKER_IP_1 = "203.0.113.42"
ATTACKER_IP_2 = "198.51.100.23"

NORMAL_PATHS = [
    '"GET / HTTP/1.1" 200 1024',
    '"GET /about HTTP/1.1" 200 512',
    '"GET /images/logo.png HTTP/1.1" 200 8421',
    '"POST /login HTTP/1.1" 200 240',
]

ATTACK_PAYLOADS = [
    # Directory Traversal
    f'{ATTACKER_IP_1} - - [DATE] "GET /../../../../etc/passwd HTTP/1.1" 404 123',
    # SQLi 1
    f'{ATTACKER_IP_2} - - [DATE] "GET /products?id=1\' OR 1=1 HTTP/1.1" 200 5000',
    # SQLi 2
    f'{ATTACKER_IP_2} - - [DATE] "POST /login?user=admin\' UNION SELECT password FROM users HTTP/1.1" 500 212',
]

def generate_timestamp():
    # log format timestamp [01/Mar/2026:06:50:00 +0000]
    return time.strftime("[%d/%b/%Y:%H:%M:%S +0000]")

def write_log(line):
    with open(LOG_FILE, 'a') as f:
        f.write(line + '\n')
    print(f"Logged: {line}")

def simulate():
    print("Starting mock traffic generator...")
    
    brute_force_counter = 0

    while True:
        timestamp = generate_timestamp()
        
        # 60% chance normal, 20% attack payload, 20% brute force
        choice = random.random()
        
        if choice < 0.6:
            # Normal
            ip = random.choice(NORMAL_IPS)
            path = random.choice(NORMAL_PATHS)
            log_line = f'{ip} - - {timestamp} {path}'
            write_log(log_line)
        elif choice < 0.8:
            # Single attack from payload
            payload = random.choice(ATTACK_PAYLOADS)
            log_line = payload.replace("[DATE]", timestamp)
            write_log(log_line)
        else:
            # Brute force (HTTP 401)
            ip = "198.51.100.99"
            
            # simulate rapid burst
            brute_force_counter += 1
            for _ in range(5):
                timestamp = generate_timestamp()
                log_line = f'{ip} - - {timestamp} "POST /login HTTP/1.1" 401 50'
                write_log(log_line)
                time.sleep(0.1)

        time.sleep(random.uniform(0.5, 2.0))

if __name__ == "__main__":
    simulate()

