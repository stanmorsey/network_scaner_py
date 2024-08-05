from scapy.all import *
import time
import smtplib
from email.mime.text import MIMEText


target_ip = "192.168.1.0/24"
known_devices_file = 'known_devices.txt'

def send_email(new_devices):
    sender = "stanley.george@shamiri.institute" 
    recipient = "georgestanley14282@gmail.com"
    subject = "New Device Detected on Network"
    body = "New devices detected:\n" + "\n".join(new_devices)

    msg = MIMEText(body)
    msg['Subject'] = subject
    msg['From'] = sender
    msg['To'] = recipient

    with smtplib.SMTP('smtpm.gmail.com', 587) as server: 
        server.starttls()
        server.login("georgestanley14282@gmail.com", "Georgethorn77!") 
        server.sendmail(sender, recipient, msg.as_string())

def get_device_list():
    arp_request = ARP(pdst=target_ip)
    broadcast = Ether(dst="ff:ff:ff:ff:ff:ff")
    arp_request_broadcast = broadcast/arp_request

    answered_list = srp(arp_request_broadcast, timeout=1, verbose=False, iface="wlan0")[0]
    return {f"{element[1].psrc} {element[1].hwsrc}" for element in answered_list}

def main():
    known_devices = get_device_list()
    with open(known_devices_file, 'r') as file:
        known_devices_old = set(file.read().strip().split('\n'))

    new_devices = known_devices - known_devices_old
    if new_devices:
        send_email(new_devices)
        with open(known_devices_file, 'w') as file:
            file.write("\n".join(known_devices))

if __name__ == "__main__":
    while True:
        main()
        time.sleep(60) 
