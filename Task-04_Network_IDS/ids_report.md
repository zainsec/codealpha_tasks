Network Intrusion Detection System (NIDS)

Tool Used:
**Snort** (installed on Kali Linux)

Objective:
To set up Snort to monitor live traffic, detect suspicious activity, and trigger alerts using built-in and custom rules.

---

Setup Steps:
1. Installed Snort using `apt install snort`
2. Set interface to `eth0` and HOME_NET to `192.168.1.0/24`
3. Ran Snort in detection mode: `sudo snort -i eth0 -A console -c /etc/snort/snort.conf`

---

Simulated Traffic:
- Ran `nmap` port scan on local IP
- Sent ICMP pings to 8.8.8.8
- Accessed test web app using `curl`

---

Alerts Captured:
- TCP stealth port scan detected
- ICMP echo requests (ping) detected
- Custom rule triggered: `"ICMP ping detected"`

---

Custom Rule Added:
snort
alert icmp any any -> any any (msg: "ICMP ping detected"; sid:1000001; rev:1;)
