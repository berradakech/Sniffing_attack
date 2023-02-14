<h1>Sniffing_attack</h1>

<h2>Description</h2>

This project involves a Man-in-the-middle and a TLS downgrade attack. 

First, the aim of the mitm.py file is to intercept sensitive information being transmitted in plaintext over the network by routing the client's traffic through the MITM container. The project makes use of Docker Compose to run two containers, the client and the MITM. The task involves parsing HTTP headers to find sensitive information such as credit card numbers and passwords.

Besides, the mitm2.py file in the TLS Downgrade folder involves downgrading the quality of a TLS connection by forcing the use of a less secure cipher suite. This is done by modifying packets on-the-fly using a man-in-the-middle attack. The TLS handshake is unencrypted, so the attacker can modify the handshake messages to force the use of a less secure cipher suite. The attack can be prevented by using HSTS (HTTP Strict Transport Security) or by deprecating weak and old cipher suites. To perform the attack, the attacker needs to understand the TLS handshake and use tools such as NetfilterQueue and Scapy to modify packets. Wireshark can be used to explore the traffic and identify the correct bytes to modify

<h2>Languages Used</h2>

- <b>Python </b> 

<!--
 ```diff
- text in red
+ text in green
! text in orange
# text in gray
@@ text in purple (and bold)@@
```
--!>
