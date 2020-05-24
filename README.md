# DNS-Hijacking
A C/C++ language tool for DNS Hijacking in UNIX/Linux System by using raw socket.

## DNSClientServer
In this folder you can find a simple implementation of DNS client and DNS server. The DNS server is a fundation for DNS Hijacking.

## DNSHijacking
In this folder you can find an implementation of DNS Hijacking, where you can specify through which interface to spoof. The part of spoofing is implemented by pcap. Once it is activated, it will send a false response to all the DNS query that it receives.
