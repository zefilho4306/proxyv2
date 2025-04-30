#!/data/data/com.termux/files/usr/bin/bash
set -e

echo "==========================================="
echo "🚀 Instalador Proxy Imperial (Alta Performance)"
echo "==========================================="

if [ ! -d "/data/data/com.termux/files" ]; then
  echo "❌ Este script só funciona no Termux."
  exit 1
fi

termux-wake-lock
mkdir -p ~/proxy_node/server ~/proxy_node/flux

echo "[1/7] 🔄 Atualizando Termux..."
pkg update -y && pkg upgrade -y

echo "[2/7] 📦 Instalando dependências..."
pkg install -y git golang wget termux-api

go version || { echo "❌ Go não está instalado corretamente!"; exit 1; }

echo ""
echo "[3/7] ⚙️ Escolha o nível do seu dispositivo:"
echo "1 = Fraco (até 3GB RAM)"
echo "2 = Médio (4-6GB RAM)"
echo "3 = Forte (6GB+ RAM)"
read -p "Escolha [1-3]: " NIVEL
[[ "$NIVEL" =~ ^[1-3]$ ]] || { echo "❌ Escolha inválida."; exit 1; }

case $NIVEL in
  1) MAX_IDLE=50; BUFFSIZE=8192 ;;
  2) MAX_IDLE=150; BUFFSIZE=16384 ;;
  3) MAX_IDLE=300; BUFFSIZE=65536 ;;
esac

cd ~/proxy_node/server

cat > proxy.go <<EOF
package main

import (
  "context"
  "flag"
  "io"
  "log"
  "net"
  "net/http"
  "os"
  "os/signal"
  "runtime"
  "syscall"
  "time"
)

var (
  listenAddr  = flag.String("listen", ":8080", "Endereço de escuta")
  bufferSize  = flag.Int("buffer", $BUFFSIZE, "Tamanho do buffer")
  connTimeout = flag.Duration("conn-timeout", 20*time.Second, "Timeout de conexão")
)

func main() {
  flag.Parse()
  runtime.GOMAXPROCS(runtime.NumCPU())

  server := &http.Server{
    Addr:              *listenAddr,
    Handler:           http.HandlerFunc(handle),
    IdleTimeout:       60 * time.Second,
    ReadHeaderTimeout: 10 * time.Second,
    MaxHeaderBytes:    1 << 18,
  }

  go func() {
    c := make(chan os.Signal, 1)
    signal.Notify(c, syscall.SIGINT, syscall.SIGTERM)
    <-c
    log.Println("🛑 Encerrando...")
    ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
    defer cancel()
    server.Shutdown(ctx)
  }()

  log.Println("🚀 Proxy iniciado em", *listenAddr)
  log.Printf("🧠 Buffer: %d KB | CPUs: %d", *bufferSize/1024, runtime.NumCPU())
  if err := server.ListenAndServe(); err != http.ErrServerClosed {
    log.Fatal("Erro:", err)
  }
}

func handle(w http.ResponseWriter, r *http.Request) {
  if r.Method == http.MethodConnect {
    handleTunnel(w, r)
  } else {
    handleHTTP(w, r)
  }
}

func handleTunnel(w http.ResponseWriter, r *http.Request) {
  dest, err := net.DialTimeout("tcp", r.Host, *connTimeout)
  if err != nil {
    http.Error(w, "Conexão falhou", http.StatusServiceUnavailable)
    return
  }

  hij, ok := w.(http.Hijacker)
  if !ok {
    http.Error(w, "Hijack não suportado", http.StatusInternalServerError)
    return
  }

  client, _, err := hij.Hijack()
  if err != nil {
    http.Error(w, "Erro no hijack", http.StatusServiceUnavailable)
    return
  }

  client.Write([]byte("HTTP/1.1 200 Connection Established\r\n\r\n"))
  go pipe(dest, client)
  go pipe(client, dest)
}

func handleHTTP(w http.ResponseWriter, r *http.Request) {
  r.RequestURI = ""
  resp, err := http.DefaultTransport.RoundTrip(r)
  if err != nil {
    http.Error(w, err.Error(), http.StatusBadGateway)
    return
  }
  defer resp.Body.Close()
  for k, v := range resp.Header {
    for _, vv := range v {
      w.Header().Add(k, vv)
    }
  }
  w.WriteHeader(resp.StatusCode)
  io.Copy(w, resp.Body)
}

func pipe(dst net.Conn, src net.Conn) {
  defer dst.Close()
  defer src.Close()
  buf := make([]byte, *bufferSize)
  dst.SetDeadline(time.Now().Add(30 * time.Second))
  src.SetDeadline(time.Now().Add(30 * time.Second))
  io.CopyBuffer(dst, src, buf)
}
EOF

echo "[4/7] 🔧 Compilando proxy Go..."
go mod init proxy && go mod tidy
go build -o proxy

cd ~/proxy_node/flux
git clone https://github.com/fatedier/frp frp_src && cd frp_src/cmd/frpc
go build -o ../../flux
cd ../../
rm -rf frp_src

CANAL="ep-$(head /dev/urandom | tr -dc a-z0-9 | head -c6)"
PORTA=$((RANDOM % 40000 + 10000))
echo "$CANAL:$PORTA" > ~/proxy_node/flux/ultima_porta.txt

cat > flux.ini <<EOF
[common]
server_addr = 185.194.205.181
server_port = 7000
login_fail_exit = false

[$CANAL]
type = tcp
local_ip = 127.0.0.1
local_port = 8080
remote_port = $PORTA
EOF

mkdir -p ~/.termux/boot

cat > ~/proxy_node/watchdog.sh <<'EOF'
#!/data/data/com.termux/files/usr/bin/bash
pgrep -f proxy_node/server/proxy > /dev/null || nohup ~/proxy_node/server/proxy -listen :8080 -buffer=16384 > ~/proxy_node/server/proxy.log 2>&1 &
pgrep -f proxy_node/flux/flux > /dev/null || nohup ~/proxy_node/flux/flux -c ~/proxy_node/flux/flux.ini > ~/proxy_node/flux/flux.log 2>&1 &
EOF
chmod +x ~/proxy_node/watchdog.sh

cat > ~/.termux/boot/autostart.sh <<EOF
#!/data/data/com.termux/files/usr/bin/bash
termux-wake-lock
sleep 5
bash ~/proxy_node/watchdog.sh
while true; do sleep 60; bash ~/proxy_node/watchdog.sh; done
EOF
chmod +x ~/.termux/boot/autostart.sh

echo "[7/7] ▶️ Iniciando serviços..."
bash ~/proxy_node/watchdog.sh

IP=$(ip a | grep inet | grep -E '192|10|172' | awk '{print $2}' | cut -d'/' -f1 | head -n1)
[ -z "$IP" ] && IP="127.0.0.1"

echo ""
echo "==========================================="
echo "✅ Proxy configurado com sucesso!"
echo "📡 IP local: $IP"
echo "🔌 Porta local: 8080"
echo "🔁 Canal FRPC: $CANAL"
echo "🌐 Porta remota liberada na VPS: $PORTA"
echo "📄 Info salva em: ~/proxy_node/flux/ultima_porta.txt"
echo "🛡️ Watchdog ativo e autostart no boot"
echo "==========================================="
