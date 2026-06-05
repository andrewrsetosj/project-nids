Project NIDS — Reflection Questions
Andrew Seto | ITP 325 Ethical Hacking and Systems Defense
Dr. Sedek - 92320

Q1: What problem does it solve?
This project is a basic NIDS that watches live traffic and flags anything suspicious like port scans, flood attacks, DNS tunneling, etc. The goal was to build something like a low-fidelity Snort from scratch to understand how these tools actually work, without relying on expensive commercial software.

Q2: What were the key technical challenges and how did you solve them?
The hardest part was keeping track of each IP's behavior over time without the program eating up memory. I used Python deques to store recent timestamps per IP and just drop old ones as new packets come in, so the memory stays bounded. The other big issue was alert spam because one SYN flood would fire hundreds of times a second, which is useless. I added a 30-second cooldown per (IP, rule) pair so it only alerts once until the attack is clearly ongoing.

Q3: What are the limitations of your approach and how could it be improved?
The system only looks at individual packets, not the full conversation, so it can't catch anything hidden inside application-layer traffic like HTTP or TLS. It also keeps all its state in memory, meaning if you restart it, the context is gone, and it can't share data with other sensors on the network. For future expansion, I'd want to persist the per-IP state to a database so the detector can survive restarts and eventually share context across multiple sensors.

Works Cited

1. "Guide to Intrusion Detection and Prevention Systems (IDPS)" — Karen Scarfone (NIST), Peter Mell (NIST) - National Institute of Standards and Technology
   https://csrc.nist.gov/publications/detail/sp/800-94/final

2. Snort — Documentation — Cisco / Snort.org
   https://www.snort.org/documents

3. Scapy — Documentation — Philippe Biondi et al.
   https://scapy.readthedocs.io/en/latest/

4. "What is an intrusion detection system (IDS)?" — IBM
   https://www.ibm.com/think/topics/intrusion-detection-system

5. "Intrusion detection system" — Wikipedia
   https://en.wikipedia.org/wiki/Intrusion_detection_system

6. "DNS Tunneling: how DNS can be (ab)used by malicious actors" — Alex Hinchliffe - Palo Alto Networks Unit 42
   https://unit42.paloaltonetworks.com/dns-tunneling-how-dns-can-be-abused-by-malicious-actors/
