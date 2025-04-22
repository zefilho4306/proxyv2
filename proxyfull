#!/data/data/com.termux/files/usr/bin/bash
set -e

echo "========================================"
echo "[*] Instalador IMPERIAL PROXY
echo "========================================"

# Verificar ambiente
if [ ! -d "/data/data/com.termux" ]; then
    echo "❌ Este script deve ser executado no Termux!"
    exit 1
fi

# [1] Atualizar e instalar dependências
echo "[1/8] Atualizando Termux e instalando dependências..."
pkg update -y && pkg upgrade -y
pkg install -y git make clang net-tools golang termux-api

# [2] Compilar 3proxy
echo "[2/8] Clonando e compilando o server..."
cd ~
rm -rf 3proxy
git clone https://github.com/3proxy/3proxy.git
cd 3proxy
make -f Makefile.Linux
mkdir -p $PREFIX/bin
cp bin/3proxy $PREFIX/bin/
chmod +x $PREFIX/bin/3proxy

# [3] Configuração do 3proxy
echo "[3/8] Configurando server..."
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

# [4] Instalar FRPC
echo "[4/8] Instalando flux..."
cd ~
rm -rf frp
git clone https://github.com/fatedier/frp || true
cd ~/frp/cmd/frpc
go build
mkdir -p ~/proxy_node/frpc
cp ./frpc ~/proxy_node/frpc/
cd ~/proxy_node/frpc
chmod +x frpc

# [5] Criar config do FRPC com porta aleatória
echo "[5/8] Gerando configuração do flux..."
RANDOM_NAME="ep-$(head /dev/urandom | tr -dc a-z0-9 | head -c6)"
RANDOM_PORT=$(( ( RANDOM % 40000 ) + 10000 ))
cat > frpc.ini <<EOF
[common]
server_addr = 185.194.205.181
server_port = 7000

[$RANDOM_NAME]
type = tcp
local_ip = 127.0.0.1
local_port = 8080
remote_port = $RANDOM_PORT
EOF

echo "NOME = $RANDOM_NAME" > INFO.txt
echo "PORTA REMOTA = $RANDOM_PORT" >> INFO.txt

# [6] Criar script de boot automático
echo "[6/8] Criando script de boot automático..."
mkdir -p ~/.termux/boot
cat > ~/.termux/boot/autostart.sh <<EOF
#!/data/data/com.termux/files/usr/bin/bash
termux-wake-lock
sleep 3
nohup env LD_LIBRARY_PATH=\$PREFIX/lib \$PREFIX/bin/3proxy \$PREFIX/etc/3proxy/3proxy.cfg > ~/3proxy.log 2>&1 &
nohup ~/proxy_node/frpc/frpc -c ~/proxy_node/frpc/frpc.ini > ~/proxy_node/frpc/frpc.log 2>&1 &
EOF
chmod +x ~/.termux/boot/autostart.sh

# [7] Start manual imediato (sem reboot)
echo "[7/8] Iniciando serviços manualmente..."
nohup env LD_LIBRARY_PATH=$PREFIX/lib $PREFIX/bin/3proxy $PREFIX/etc/3proxy/3proxy.cfg > ~/3proxy.log 2>&1 &
nohup ~/proxy_node/frpc/frpc -c ~/proxy_node/frpc/frpc.ini > ~/proxy_node/frpc/frpc.log 2>&1 &

# [8] Status final
IP=$(ifconfig 2>/dev/null | grep -E 'inet (192|10|172)' | awk '{print $2}' | head -n1)
echo ""
echo "========================================"
echo "✅ Instalação concluída com sucesso!"
echo "----------------------------------------"
echo "IP local: $IP"
echo "HTTP Proxy: $IP:8080"
echo "FRPC Sessão: $RANDOM_NAME"
echo "Porta Remota: $RANDOM_PORT"
echo "----------------------------------------"
echo "[!] Instale o Termux:Boot: https://f-droid.org/packages/com.termux.boot"
echo "[!] Depois reinicie o celular para iniciar tudo automaticamente."
echo "========================================"
