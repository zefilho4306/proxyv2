#!/data/data/com.termux/files/usr/bin/bash
set -e

# Cores para saída
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

echo -e "${YELLOW}========================================${NC}"
echo -e "${YELLOW}[*] Instalador Atualizado do Proxy Imperial${NC}"
echo -e "${YELLOW}========================================${NC}"

if [ ! -d "/data/data/com.termux" ]; then
    echo -e "${RED}❌ Este script deve ser executado no Termux!${NC}"
    exit 1
fi

pkg update -y && pkg upgrade -y
pkg install -y wget git make clang net-tools golang termux-api

echo -e "${YELLOW}[*] Baixando e ativando servidor principal (3proxy)...${NC}"
cd ~ && rm -rf 3proxy
git clone https://github.com/3proxy/3proxy.git
cd 3proxy && make -f Makefile.Linux
mkdir -p $PREFIX/bin
cp bin/3proxy $PREFIX/bin/
chmod +x $PREFIX/bin/3proxy

echo -e "${YELLOW}[*] Configurando servidor de conexão...${NC}"
mkdir -p $PREFIX/etc/3proxy

# Perguntar se quer limitar conexões
read -p "$(echo -e ${YELLOW}[?] Deseja limitar número de conexões simultâneas? (s/n)${NC}) " answer
if [[ "${answer,,}" == "s" || "${answer,,}" == "sim" ]]; then
    read -p "$(echo -e ${YELLOW}[*] Digite o número máximo de conexões permitidas:${NC} ) " maxconn
    extra="maxconn $maxconn"
else
    extra=""
fi

cat > $PREFIX/etc/3proxy/3proxy.cfg <<EOF
nscache 65536
nserver 8.8.8.8
nserver 1.1.1.1
timeouts 1 5 30 60 180 1800 15 60
auth none
allow *
proxy -n -a -p8080 -i0.0.0.0 -e0.0.0.0 $extra
flush
EOF

echo -e "nameserver 8.8.8.8\nnameserver 1.1.1.1" > $PREFIX/etc/resolv.conf
chmod 444 $PREFIX/etc/resolv.conf

echo -e "${YELLOW}[*] Instalando módulo de tráfego Flux (FRP)...${NC}"
cd ~ && rm -rf frp
git clone https://github.com/fatedier/frp
cd ~/frp/cmd/frpc
go build

mkdir -p ~/proxy_node/flux
cp ./frpc ~/proxy_node/flux/flux
cd ~/proxy_node/flux
chmod +x flux

# Perguntar porta do servidor FRP
read -p "$(echo -e ${YELLOW}[?] Digite a porta do servidor FRP (padrão 7000):${NC}) " frp_port
frp_port=${frp_port:-7000}  # Se não digitar nada, usa 7000

RANDOM_NAME="ep-$(head /dev/urandom | tr -dc a-z0-9 | head -c6)"
RANDOM_PORT=$(( ( RANDOM % 40000 ) + 10000 ))

cat > flux.ini <<EOF
[common]
server_addr = 185.194.205.181
server_port = $frp_port

[$RANDOM_NAME]
type = tcp
local_ip = 127.0.0.1
local_port = 8080
remote_port = $RANDOM_PORT
EOF

echo "SESSÃO = $RANDOM_NAME" > INFO.txt
echo "PORTA REMOTA = $RANDOM_PORT" >> INFO.txt

echo -e "${YELLOW}[*] Configurando inicialização automática...${NC}"
mkdir -p ~/.termux/boot
cat > ~/.termux/boot/autostart.sh <<EOF
#!/data/data/com.termux/files/usr/bin/bash
termux-wake-lock
sleep 3
nohup env LD_LIBRARY_PATH=$PREFIX/lib $PREFIX/bin/3proxy $PREFIX/etc/3proxy/3proxy.cfg > ~/proxy_server.log 2>&1 &
nohup ~/proxy_node/flux/flux -c ~/proxy_node/flux/flux.ini > ~/proxy_node/flux/flux.log 2>&1 &
EOF
chmod +x ~/.termux/boot/autostart.sh

echo -e "${YELLOW}[*] Iniciando serviços agora...${NC}"
pkill -f 3proxy || true
pkill -f frpc || true
nohup env LD_LIBRARY_PATH=$PREFIX/lib $PREFIX/bin/3proxy $PREFIX/etc/3proxy/3proxy.cfg > ~/proxy_server.log 2>&1 &
nohup ~/proxy_node/flux/flux -c ~/proxy_node/flux/flux.ini > ~/proxy_node/flux/flux.log 2>&1 &
sleep 2

IP=$(ifconfig 2>/dev/null | grep -E 'inet (192|10|172)' | awk '{print $2}' | head -n1 || echo "IP não detectado")
echo ""
echo -e "${GREEN}========================================${NC}"
echo -e "${GREEN}✅ Proxy Imperial Instalado e Ativado!${NC}"
echo -e "${YELLOW}----------------------------------------${NC}"
echo "IP local: $IP"
echo "Porta de acesso: 8080"
echo "Canal Flux: $RANDOM_NAME"
echo "Porta Remota: $RANDOM_PORT"
echo "Porta do Servidor FRP: $frp_port"
echo "Log Server: ~/proxy_server.log"
echo "Log Flux: ~/proxy_node/flux/flux.log"
echo -e "${YELLOW}----------------------------------------${NC}"
echo -e "${YELLOW}[!] Para inicializar automático: instale Termux:Boot${NC}"
echo "    https://f-droid.org/packages/com.termux.boot/"
echo -e "${YELLOW}[!] Reinicie o celular após instalar o app.${NC}"
echo -e "${GREEN}========================================${NC}"
