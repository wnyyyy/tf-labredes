from dnslib import DNSRecord, DNSHeader, RR, QTYPE, A
from dnslib.server import DNSServer
import logging

DEFAULT_GATEWAY_IP = '192.168.109.1'

class CustomDNSResolver:
    def resolve(self, request, handler):
        reply = request.reply()
        qname = request.q.qname
        qtype = QTYPE[request.q.qtype]
        logging.info(f'Pedido DNS recebido para: {qname}')
        
        # Logica de DNS custom
        if qname.matchGlob("example2.com."):
            reply.add_answer(RR(qname, QTYPE.A, rdata=A("142.250.189.174")))
            logging.info(f'Respondendo com o IP: 142.250.189.174 for {qname}')
        else:
            reply.header.rcode = getattr(DNSHeader.RCODE, "NXDOMAIN")
            logging.info(f'Nenhum domínio encontrado para: {qname}')
        
        return reply

if __name__ == '__main__':
    logging.basicConfig(level=logging.INFO)
    resolver = CustomDNSResolver()
    dns_server = DNSServer(resolver, port=53, address=DEFAULT_GATEWAY_IP)
    logging.info("Iniciando servidor de DNS custom na porta 53")
    dns_server.start_thread()

    try:
        while True:
            pass
    except KeyboardInterrupt:
        logging.info("Parando servidor DNS")
        dns_server.stop()
