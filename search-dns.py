from concurrent.futures import ThreadPoolExecutor
import dns.resolver
import argparse
import threading

# Initialize a counter and a lock object
counter = 0
lock = threading.Lock()

def check_spf(domain):
    global counter

    try:
        answers = dns.resolver.resolve(domain, 'TXT')
        for rdata in answers:
            for txt_string in rdata.strings:
                try:
                    decoded_txt = txt_string.decode('utf-8')
                except UnicodeDecodeError:
                    decoded_txt = txt_string.decode('utf-8', 'ignore')

                if "relay.mailchannels.net" in decoded_txt:
                    print(f"{domain} can be spoofed")
    except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN):
        pass

    # Safely update counter
    with lock:
        counter += 1
        if counter % 10000 == 0:
            print(f"Processed {counter} out of {len(domains)} domains.")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='Check SPF records for domains from a file.')
    parser.add_argument('filename', help='Path to the file containing the list of domains, one per line.')
    args = parser.parse_args()

    try:
        with open(args.filename, 'r') as f:
            domains = f.read().splitlines()
    except FileNotFoundError:
        print("File not found. Please provide a valid file path.")
        exit(1)

    with ThreadPoolExecutor(max_workers=50) as executor:  # <-- This is where you make the change
        executor.map(check_spf, domains)

