from http.server import BaseHTTPRequestHandler, HTTPServer
import requests
import logging

# Replace with the IP address of your default gateway
DEFAULT_GATEWAY_IP = '192.168.109.1'

class ProxyHTTPRequestHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        original_url = self.path
        logging.info(f'Pedido recebido para a URL: {original_url}')
        
        # Substitui example.com com google.com
        if 'example.com' in original_url:
            redirect_url = original_url.replace('example.com', 'google.com')
            logging.info(f'Redirecionando a URL de {original_url} para {redirect_url}')
        else:
            redirect_url = original_url
        
        # Redireciona o pedido para a nova URL
        try:
            response = requests.get(redirect_url)
            logging.info(f'Pedido redirecionado para {redirect_url}, resposta recebida com status code: {response.status_code}')
            
            # Envia resposta de volta para o cliente
            self.send_response(response.status_code)
            for header, value in response.headers.items():
                self.send_header(header, value)
            self.end_headers()
            self.wfile.write(response.content)
        except Exception as e:
            logging.error(f'Erro redirecionando pedido: {e}')
            self.send_response(500)
            self.end_headers()
            self.wfile.write(b'Internal Server Error')

def run_server(server_class=HTTPServer, handler_class=ProxyHTTPRequestHandler, port=80):
    logging.basicConfig(level=logging.INFO)
    server_address = (DEFAULT_GATEWAY_IP, port)
    httpd = server_class(server_address, handler_class)
    logging.info(f'Iniciando servidor proxy emS {DEFAULT_GATEWAY_IP}:{port}')
    httpd.serve_forever()

if __name__ == '__main__':
    run_server()
