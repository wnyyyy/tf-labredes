from http.server import BaseHTTPRequestHandler, HTTPServer
import requests
import logging

# Replace with the IP address of your default gateway
DEFAULT_GATEWAY_IP = '192.168.109.1'

class ProxyHTTPRequestHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        # Parse the original request URL
        original_url = self.path
        logging.info(f'Received request for URL: {original_url}')
        
        # Replace example.com with google.com
        if 'example.com' in original_url:
            redirect_url = original_url.replace('example.com', 'google.com')
            logging.info(f'Redirecting URL from {original_url} to {redirect_url}')
        else:
            redirect_url = original_url
        
        # Forward the request to the new URL
        try:
            response = requests.get(redirect_url)
            logging.info(f'Forwarded request to {redirect_url}, received response with status code: {response.status_code}')
            
            # Send response back to the client
            self.send_response(response.status_code)
            for header, value in response.headers.items():
                self.send_header(header, value)
            self.end_headers()
            self.wfile.write(response.content)
        except Exception as e:
            logging.error(f'Error forwarding request: {e}')
            self.send_response(500)
            self.end_headers()
            self.wfile.write(b'Internal Server Error')

def run_server(server_class=HTTPServer, handler_class=ProxyHTTPRequestHandler, port=80):
    logging.basicConfig(level=logging.INFO)
    server_address = (DEFAULT_GATEWAY_IP, port)
    httpd = server_class(server_address, handler_class)
    logging.info(f'Starting proxy server on {DEFAULT_GATEWAY_IP}:{port}')
    httpd.serve_forever()

if __name__ == '__main__':
    run_server()
