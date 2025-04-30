#!/data/data/com.termux/files/usr/bin/bash
set -e

echo "========================================"
echo "[*] Instalador do Proxy Imperial (Python)"
echo "========================================"

if [ ! -d "/data/data/com.termux" ]; then
    echo "❌ Este script deve ser executado no Termux!"
    exit 1
fi

pkg update -y && pkg upgrade -y
pkg install -y git python golang termux-api

# Escolha de desempenho
echo ""
echo "[*] Qual o nível de desempenho do celular?"
echo "1 = Fraco (2-3GB RAM)"
echo "2 = Médio (4GB RAM)"
echo "3 = Forte (6GB+)"
read -p "Escolha [1-3]: " NIVEL

if [ "$NIVEL" = "1" ]; then
  THREADS=30
  BUFFER=2048
  TIMEOUT=15
elif [ "$NIVEL" = "2" ]; then
  THREADS=50
  BUFFER=4096
  TIMEOUT=20
else
  THREADS=80
  BUFFER=8192
  TIMEOUT=30
fi

mkdir -p ~/proxy_node/server

echo "[*] Criando servidor proxy Python..."
cat > ~/proxy_node/server/proxy.py <<EOF
import socket, select, ssl
from urllib.parse import urlparse
from concurrent.futures import ThreadPoolExecutor

class HighPerformanceProxy:
    def __init__(self):
        self.pool = ThreadPoolExecutor(max_workers=$THREADS)
        self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_KEEPALIVE, 1)
        self.server_socket.bind(('0.0.0.0', 8080))
        self.server_socket.listen(200)
        print(f"[Proxy] Ativo na porta 8080 com $THREADS threads")

    def handle_request(self, client_socket):
        try:
            request = client_socket.recv($BUFFER)
            if not request:
                client_socket.close()
                return
            first_line = request.split(b'\\n')[0]
            method, url, _ = first_line.split()
            host, port = self.extract_target(url.decode())
            with socket.create_connection((host, port), timeout=$TIMEOUT) as server_socket:
                if port == 443:
                    context = ssl.create_default_context()
                    server_socket = context.wrap_socket(server_socket, server_hostname=host)
                    client_socket.sendall(b'HTTP/1.1 200 Connection Established\\r\\n\\r\\n')
                else:
                    server_socket.sendall(request)
                self.relay_data(client_socket, server_socket)
        except Exception as e:
            print("[ERRO]", str(e)[:100])
        finally:
            client_socket.close()

    def extract_target(self, url):
        parsed = urlparse(url if url.startswith('http') else 'http://' + url)
        return parsed.hostname, parsed.port or (443 if parsed.scheme == 'https' else 80)

    def relay_data(self, client_socket, server_socket):
        sockets = [client_socket, server_socket]
        while True:
            readable, _, _ = select.select(sockets, [], [], 30)
            if not readable:
                break
            for sock in readable:
                data = sock.recv($BUFFER)
                if not data:
                    return
                (server_socket if sock is client_socket else client_socket).sendall(data)

    def run(self):
        try:
            while True:
                client_socket, _ = self.server_socket.accept()
                self.pool.submit(self.handle_request, client_socket)
        except KeyboardInterrupt:
            self.pool.shutdown(wait=False)
            self.server_socket.close()

if __name__ == '__main__':
    proxy = HighPerformanceProxy()
    proxy.run()
EOF

# Instala frpc como no script original
echo "[*] Instalando o módulo de tráfego Flux..."
cd ~ && rm -rf frp
git clone https://github.com/fatedier/frp
cd ~/frp/cmd/frpc
go build

mkdir -p ~/proxy_node/flux
cp ./frpc ~/proxy_node/flux/flux
cd ~/proxy_node/flux
chmod +x flux

RANDOM_NAME="ep-$(head /dev/urandom | tr -dc a-z0-9 | head -c6)"
RANDOM_PORT=$(( ( RANDOM % 40000 ) + 10000 ))

cat > flux.ini <<EOF
[common]
server_addr = 185.194.205.181
server_port = 7000

[$RANDOM_NAME]
type = tcp
local_ip = 127.0.0.1
local_port = 8080
remote_port = $RANDOM_PORT
EOF

echo "SESSÃO = $RANDOM_NAME" > INFO.txt
echo "PORTA REMOTA = $RANDOM_PORT" >> INFO.txt

# Criação do autostart
echo "[*] Ativando inicialização automática no boot..."
mkdir -p ~/.termux/boot
cat > ~/.termux/boot/autostart.sh <<EOF
#!/data/data/com.termux/files/usr/bin/bash
termux-wake-lock
sleep 3
nohup python ~/proxy_node/server/proxy.py > ~/proxy_node/server/proxy.log 2>&1 &
nohup ~/proxy_node/flux/flux -c ~/proxy_node/flux/flux.ini > ~/proxy_node/flux/flux.log 2>&1 &
EOF
chmod +x ~/.termux/boot/autostart.sh

# Inicia imediatamente
echo "[*] Iniciando proxy e túnel agora..."
nohup python ~/proxy_node/server/proxy.py > ~/proxy_node/server/proxy.log 2>&1 &
nohup ~/proxy_node/flux/flux -c ~/proxy_node/flux/flux.ini > ~/proxy_node/flux/flux.log 2>&1 &

# Exibe status final
IP=$(ifconfig 2>/dev/null | grep -E 'inet (192|10|172)' | awk '{print $2}' | head -n1)
echo ""
echo "========================================"
echo "✅ Proxy Imperial (Python) ativado com sucesso!"
echo "----------------------------------------"
echo "IP local: $IP"
echo "Porta: 8080"
echo "Canal Flux: $RANDOM_NAME"
echo "Porta Remota: $RANDOM_PORT"
echo "Logs: ~/proxy_node/server/proxy.log"
echo "----------------------------------------"
echo "[!] Para iniciar no boot: instale o Termux:Boot"
echo "    https://f-droid.org/packages/com.termux.boot"
echo "[!] Reinicie o celular após instalar o app."
echo "========================================"
