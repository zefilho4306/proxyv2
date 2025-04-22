#!/data/data/com.termux/files/usr/bin/bash
set -e

echo "========================================"
echo "[*] Instalador do Proxy Imperial"
echo "========================================"

if [ ! -d "/data/data/com.termux" ]; then
    echo "❌ Este script deve ser executado no Termux!"
    exit 1
fi

pkg update -y && pkg upgrade -y
pkg install -y git make clang net-tools golang termux-api

echo "[*] Baixando e ativando servidor principal..."
cd ~ && rm -rf 3proxy
git clone https://github.com/3proxy/3proxy.git
cd 3proxy && make -f Makefile.Linux
mkdir -p $PREFIX/bin
cp bin/3proxy $PREFIX/bin/
chmod +x $PREFIX/bin/3proxy

echo "[*] Configurando servidor de conexão..."
mkdir -p $PREFIX/etc/3proxy
cat > $PREFIX/etc/3proxy/3proxy.cfg <<EOF
nscache 65536
nserver 8.8.8.8
nserver 1.1.1.1
timeouts 1 5 30 60 180 1800 15 60
auth none
allow *
proxy -n -a -p8080 -i0.0.0.0 -e0.0.0.0
flush
EOF

echo -e "nameserver 8.8.8.8\nnameserver 1.1.1.1" > $PREFIX/etc/resolv.conf
chmod 444 $PREFIX/etc/resolv.conf

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

echo "[*] Ativando inicialização automática do Proxy Imperial..."
mkdir -p ~/.termux/boot
cat > ~/.termux/boot/autostart.sh <<EOF
#!/data/data/com.termux/files/usr/bin/bash
termux-wake-lock
sleep 3
nohup env LD_LIBRARY_PATH=\$PREFIX/lib \$PREFIX/bin/3proxy \$PREFIX/etc/3proxy/3proxy.cfg > ~/proxy_server.log 2>&1 &
nohup ~/proxy_node/flux/flux -c ~/proxy_node/flux/flux.ini > ~/proxy_node/flux/flux.log 2>&1 &
EOF
chmod +x ~/.termux/boot/autostart.sh

echo "[*] Iniciando agora o servidor e o canal Flux..."
nohup env LD_LIBRARY_PATH=$PREFIX/lib $PREFIX/bin/3proxy $PREFIX/etc/3proxy/3proxy.cfg > ~/proxy_server.log 2>&1 &
nohup ~/proxy_node/flux/flux -c ~/proxy_node/flux/flux.ini > ~/proxy_node/flux/flux.log 2>&1 &

IP=$(ifconfig 2>/dev/null | grep -E 'inet (192|10|172)' | awk '{print $2}' | head -n1)
echo ""
echo "========================================"
echo "✅ Proxy Imperial ativado com sucesso!"
echo "----------------------------------------"
echo "IP local: $IP"
echo "Porta de acesso: 8080"
echo "Canal Flux: $RANDOM_NAME"
echo "Porta Remota: $RANDOM_PORT"
echo "Log Server: ~/proxy_server.log"
echo "Log Flux: ~/proxy_node/flux/flux.log"
echo "----------------------------------------"
echo "[!] Para iniciar no boot: instale o Termux:Boot"
echo "    https://f-droid.org/packages/com.termux.boot"
echo "[!] Reinicie o celular após instalar o app."
echo "========================================"
