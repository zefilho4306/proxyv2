#!/data/data/com.termux/files/usr/bin/bash
set -e

echo "========================================"
echo "[*] Instalador do Proxy Imperial (GoLang)"
echo "========================================"

if [ ! -d "/data/data/com.termux" ]; then
    echo "❌ Este script deve ser executado no Termux!"
    exit 1
fi

pkg update -y && pkg upgrade -y
pkg install -y git golang termux-api

termux-wake-lock

echo ""
echo "[*] Qual o nível de desempenho do celular?"
echo "1 = Fraco (2-3GB RAM)"
echo "2 = Médio (4GB RAM)"
echo "3 = Forte (6GB+)"
read -p "Escolha [1-3]: " NIVEL

if [ "$NIVEL" = "1" ]; then
  MAX_IDLE=50
elif [ "$NIVEL" = "2" ]; then
  MAX_IDLE=150
else
  MAX_IDLE=300
fi

mkdir -p ~/proxy_node/server
cd ~/proxy_node/server

echo "[*] Criando código Go do proxy..."
cat > proxy.go <<'EOF'
package main

import (
	"context"
	"crypto/tls"
	"flag"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"runtime"
	"runtime/debug"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"golang.org/x/time/rate"
)

var (
	listenAddr    = flag.String("listen", ":8080", "Endereço de escuta")
	maxIdleConns  = flag.Int("max-idle", 200, "Conexões ociosas máximas")
	maxIdleTime   = flag.Duration("idle-time", 2*time.Minute, "Tempo máximo ocioso")
	connTimeout   = flag.Duration("conn-timeout", 15*time.Second, "Timeout de conexão")
	enableMetrics = flag.Bool("metrics", true, "Habilitar métricas")
	insecure      = flag.Bool("insecure", false, "Ignorar SSL")
	rateLimit     = flag.Int("rate-limit", 0, "Limite req/s")
)

var (
	activeConns    int64
	totalRequests  int64
	activeRequests int64
)

func main() {
	flag.Parse()
	optimizeForMobile()

	transport := createOptimizedTransport()
	server := &http.Server{
		Addr:              *listenAddr,
		Handler:           proxyHandler(transport),
		IdleTimeout:       *connTimeout,
		ReadHeaderTimeout: 5 * time.Second,
		MaxHeaderBytes:    1 << 18,
	}

	go handleSignals(server)
	if *enableMetrics {
		go resourceMonitor()
	}

	log.Printf("🚀 Proxy iniciado em %s (Go %s)", *listenAddr, runtime.Version())
	log.Printf("💻 CPUs: %d | Goroutines: %d", runtime.NumCPU(), runtime.NumGoroutine())

	if err := server.ListenAndServe(); err != http.ErrServerClosed {
		log.Fatalf("Erro fatal: %v", err)
	}
}

func optimizeForMobile() {
	runtime.GOMAXPROCS(runtime.NumCPU())
	debug.SetGCPercent(30)
	debug.SetMaxStack(16 << 18)
	if err := syscall.Setpriority(syscall.PRIO_PROCESS, 0, -10); err == nil {
		log.Println("Prioridade do processo aumentada")
	}
}

func createOptimizedTransport() *http.Transport {
	return &http.Transport{
		DialContext: (&net.Dialer{
			Timeout:       *connTimeout,
			KeepAlive:     30 * time.Second,
			FallbackDelay: 300 * time.Millisecond,
			DualStack:     true,
		}).DialContext,
		MaxIdleConns:        *maxIdleConns,
		MaxIdleConnsPerHost: runtime.NumCPU() * 4,
		IdleConnTimeout:     *maxIdleTime,
		TLSHandshakeTimeout: 8 * time.Second,
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: *insecure,
			MinVersion:         tls.VersionTLS12,
		},
		ForceAttemptHTTP2:     true,
		ExpectContinueTimeout: 1 * time.Second,
	}
}

func proxyHandler(transport *http.Transport) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if *rateLimit > 0 && !limiter.Allow() {
			http.Error(w, "Rate limit excedido", http.StatusTooManyRequests)
			return
		}
		atomic.AddInt64(&activeRequests, 1)
		defer atomic.AddInt64(&activeRequests, -1)
		atomic.AddInt64(&totalRequests, 1)
		atomic.AddInt64(&activeConns, 1)
		defer atomic.AddInt64(&activeConns, -1)
		defer recoverPanic()

		if r.Method == http.MethodConnect {
			handleTunnel(w, r)
		} else {
			handleHTTP(w, r, transport)
		}
	})
}

func handleTunnel(w http.ResponseWriter, r *http.Request) {
	dest, err := net.DialTimeout("tcp", r.Host, *connTimeout)
	if err != nil {
		http.Error(w, err.Error(), http.StatusServiceUnavailable)
		return
	}
	w.WriteHeader(http.StatusOK)
	hj, ok := w.(http.Hijacker)
	if !ok {
		dest.Close()
		http.Error(w, "Hijack não suportado", http.StatusInternalServerError)
		return
	}
	client, _, err := hj.Hijack()
	if err != nil {
		dest.Close()
		http.Error(w, err.Error(), http.StatusServiceUnavailable)
		return
	}
	go pipe(dest, client)
	go pipe(client, dest)
}

func handleHTTP(w http.ResponseWriter, r *http.Request, transport *http.Transport) {
	req := r.Clone(r.Context())
	req.RequestURI = ""
	req.Close = true
	resp, err := transport.RoundTrip(req)
	if err != nil {
		http.Error(w, "Erro: "+err.Error(), http.StatusBadGateway)
		return
	}
	defer resp.Body.Close()
	for k, vals := range resp.Header {
		for _, v := range vals {
			w.Header().Add(k, v)
		}
	}
	w.WriteHeader(resp.StatusCode)
	io.Copy(w, resp.Body)
}

func pipe(dst io.WriteCloser, src io.ReadCloser) {
	defer dst.Close()
	defer src.Close()
	buf := bufferPool.Get().(*[]byte)
	defer bufferPool.Put(buf)
	io.CopyBuffer(dst, src, *buf)
}

var (
	bufferPool = sync.Pool{
		New: func() interface{} {
			b := make([]byte, 32*1024)
			return &b
		},
	}
	limiter *rate.Limiter
)

func init() {
	if *rateLimit > 0 {
		limiter = rate.NewLimiter(rate.Limit(*rateLimit), *rateLimit*2)
	}
}

func recoverPanic() {
	if r := recover(); r != nil {
		log.Printf("Recovered: %v", r)
	}
}

func resourceMonitor() {
	for {
		var m runtime.MemStats
		runtime.ReadMemStats(&m)
		log.Printf("📊 Conns: %d | Reqs: %d | Goroutines: %d | Mem: %.2fMB",
			atomic.LoadInt64(&activeConns),
			atomic.LoadInt64(&totalRequests),
			runtime.NumGoroutine(),
			float64(m.Alloc)/1024/1024)
		time.Sleep(10 * time.Second)
	}
}

func handleSignals(srv *http.Server) {
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)
	<-sig
	log.Println("🛑 Encerrando...")
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	srv.Shutdown(ctx)
}
EOF

echo "[*] Compilando proxy..."
go mod init proxy
go get golang.org/x/time/rate
go mod tidy
go build -o proxy
chmod +x proxy

echo "[*] Instalando frpc..."
cd ~
git clone https://github.com/fatedier/frp
cd ~/frp/cmd/frpc
go build
mkdir -p ~/proxy_node/flux
cp frpc ~/proxy_node/flux/flux
chmod +x ~/proxy_node/flux/flux

RANDOM_NAME="ep-$(head /dev/urandom | tr -dc a-z0-9 | head -c6)"
RANDOM_PORT=$(( ( RANDOM % 40000 ) + 10000 ))

cat > ~/proxy_node/flux/flux.ini <<EOF
[common]
server_addr = 185.194.205.181
server_port = 7000

[$RANDOM_NAME]
type = tcp
local_ip = 127.0.0.1
local_port = 8080
remote_port = $RANDOM_PORT
EOF

mkdir -p ~/.termux/boot
cat > ~/.termux/boot/autostart.sh <<EOF
#!/data/data/com.termux/files/usr/bin/bash
termux-wake-lock
sleep 3
nohup ~/proxy_node/server/proxy -listen :8080 -max-idle=$MAX_IDLE > ~/proxy_node/server/proxy.log 2>&1 &
nohup ~/proxy_node/flux/flux -c ~/proxy_node/flux/flux.ini > ~/proxy_node/flux/flux.log 2>&1 &
EOF
chmod +x ~/.termux/boot/autostart.sh

echo "[*] Iniciando agora..."
nohup ~/proxy_node/server/proxy -listen :8080 -max-idle=$MAX_IDLE > ~/proxy_node/server/proxy.log 2>&1 &
nohup ~/proxy_node/flux/flux -c ~/proxy_node/flux/flux.ini > ~/proxy_node/flux/flux.log 2>&1 &

IP=$(ip a | grep inet | grep -E '192|10|172' | awk '{print $2}' | cut -d'/' -f1 | head -n1)
echo ""
echo "========================================"
echo "✅ Proxy Imperial (Go) ativado com sucesso!"
echo "IP local: $IP"
echo "Porta: 8080"
echo "Canal: $RANDOM_NAME"
echo "Remoto: $RANDOM_PORT"
echo "Logs: ~/proxy_node/server/proxy.log"
echo "========================================"
echo "[!] Instale o Termux:Boot para iniciar ao ligar"
