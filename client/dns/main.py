from dnslib import DNSRecord, DNSHeader, RR, QTYPE, A
from dnslib.server import DNSServer
import logging

DEFAULT_GATEWAY_IP = '192.168.109.1'

class CustomDNSResolver:
    def resolve(self, request, handler):
        reply = request.reply()
        qname = request.q.qname
        qtype = QTYPE[request.q.qtype]
        logging.info(f'Received DNS request for: {qname}')
        
        # Custom DNS resolution logic
        if qname.matchGlob("example.com."):
            reply.add_answer(RR(qname, QTYPE.A, rdata=A("142.250.189.174")))
            logging.info(f'Responding with IP: 142.250.189.174 for {qname}')
        else:
            reply.header.rcode = getattr(DNSHeader.RCODE, "NXDOMAIN")
            logging.info(f'No matching domain found for: {qname}')
        
        return reply

if __name__ == '__main__':
    logging.basicConfig(level=logging.INFO)
    resolver = CustomDNSResolver()
    dns_server = DNSServer(resolver, port=53, address=DEFAULT_GATEWAY_IP)
    logging.info("Starting custom DNS server on port 53")
    dns_server.start_thread()

    try:
        while True:
            pass
    except KeyboardInterrupt:
        logging.info("Stopping DNS server")
        dns_server.stop()
