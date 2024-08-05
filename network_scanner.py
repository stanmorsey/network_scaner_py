from scapy.all import ARP, Ether, srp
import time
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart

def scan_network(target_ip):
    arp_request = ARP(pdst=target_ip)
    broadcast = Ether(dst="ff:ff:ff:ff:ff:ff")
    arp_request_broadcast = broadcast/arp_request

    answered_list = srp(arp_request_broadcast, timeout=1, verbose=False)[0]

    devices_list = []
    for element in answered_list:
        device_info = {'ip': element[1].psrc, 'mac': element[1].hwsrc}
        devices_list.append(device_info)

    return devices_list

def display_devices(devices):
    print("IP Address\t\tMAC Address")
    print("-----------------------------------------")
    for device in devices:
        print(f"{device['ip']}\t\t{device['mac']}")

def send_email(subject, body, to_email, from_email, smtp_server, smtp_port, smtp_user, smtp_password):
    msg = MIMEMultipart()
    msg['From'] = from_email
    msg['To'] = to_email
    msg['Subject'] = subject

    msg.attach(MIMEText(body, 'plain'))

    with smtplib.SMTP(smtp_server, smtp_port) as server:
        server.starttls()
        server.login(smtp_user, smtp_password)
        server.sendmail(from_email, to_email, msg.as_string())

if __name__ == "__main__":
    target_ip = "192.168.1.1/24"
    known_devices = set()

    while True:
        devices = scan_network(target_ip)
        current_devices = {device['ip'] for device in devices}

        new_devices = current_devices - known_devices

        if new_devices:
            for device in devices:
                if device['ip'] in new_devices:
                    subject = "New Device Alert"
                    body = f"New device detected:\nIP: {device['ip']}\nMAC: {device['mac']}"
                    to_email = "stanley.george@shamiri.institute"
                    from_email = "georgestanley14282@gmail.com"
                    smtp_server = "smtp.gmail.com"
                    smtp_port = 587
                    smtp_user = "georgestanley14282@gmail.com"
                    smtp_password = "Georgethorn77!"

                    send_email(subject, body, to_email, from_email, smtp_server, smtp_port, smtp_user, smtp_password)

            known_devices.update(new_devices)

        display_devices(devices)
        time.sleep(60)  


