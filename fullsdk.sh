#!/data/data/com.termux/files/usr/bin/bash
set -e

# Constants
CONFIG_DIR="$HOME/proxy_node/config"
LOG_DIR="$HOME/proxy_node/logs"
CONFIG_FILE="$CONFIG_DIR/proxy_imperial.conf"
PROXY_CFG="$PREFIX/etc/3proxy/3proxy.cfg"
FRP_DIR="$HOME/proxy_node/flux"
FRP_INI="$FRP_DIR/flux.ini"
BOOT_SCRIPT="$HOME/.termux/boot/autostart.sh"
VERSION="2.0.0"
SCRIPT_NAME="Proxy Imperial Installer"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

# Logging setup
LOG_FILE="$LOG_DIR/install_$(date +%F_%H-%M-%S).log"
mkdir -p "$LOG_DIR"
exec 3>&1 1>>"$LOG_FILE" 2>&1

log() {
    echo -e "[$(date +%F\ %T)] $1" | tee /dev/fd/3
}

error_exit() {
    log "${RED}❌ $1${NC}"
    exit 1
}

check_termux() {
    [[ -d "/data/data/com.termux" ]] || error_exit "Este script deve ser executado no Termux!"
}

load_config() {
    mkdir -p "$CONFIG_DIR"
    if [[ ! -f "$CONFIG_FILE" ]]; then
        cat > "$CONFIG_FILE" <<'EOF'
# Proxy Imperial Configuration
PROXY_PORT=8080
FRP_SERVER_ADDR=185.194.205.181
FRP_SERVER_PORT=7000
DNS_SERVERS="8.8.8.8 1.1.1.1"
LOG_LEVEL=info
EOF
    fi
    source "$CONFIG_FILE"
}

prompt_frp_port() {
    log "${YELLOW}[?] Deseja alterar a porta do servidor FRP? (atual: $FRP_SERVER_PORT) [s/n]${NC}"
    read -r response
    if [[ "${response,,}" == "s" || "${response,,}" == "sim" ]]; then
        log "${YELLOW}[*] Digite a nova porta do servidor FRP:${NC}"
        read -r new_port
        if [[ ! "$new_port" =~ ^[0-9]+$ || "$new_port" -lt 1 || "$new_port" -gt 65535 ]]; then
            error_exit "Porta inválida. Deve ser um número entre 1 e 65535."
        fi
        FRP_SERVER_PORT="$new_port"
        sed -i "s/FRP_SERVER_PORT=.*/FRP_SERVER_PORT=$FRP_SERVER_PORT/" "$CONFIG_FILE"
        log "${GREEN}[*] Porta do servidor FRP alterada para $FRP_SERVER_PORT${NC}"
    else
        log "${GREEN}[*] Mantendo porta padrão do servidor FRP: $FRP_SERVER_PORT${NC}"
    fi
}

install_dependencies() {
    log "${YELLOW}[*] Atualizando pacotes e instalando dependências...${NC}"
    pkg update -y && pkg upgrade -y
    pkg install -y git make clang net-tools golang termux-api || error_exit "Falha ao instalar dependências"
}

install_3proxy() {
    log "${YELLOW}[*] Instalando 3proxy...${NC}"
    cd ~ && rm -rf 3proxy
    git clone https://github.com/3proxy/3proxy.git || error_exit "Falha ao clonar 3proxy"
    cd 3proxy && make -f Makefile.Linux || error_exit "Falha ao compilar 3proxy"
    mkdir -p "$PREFIX/bin"
    cp bin/3proxy "$PREFIX/bin/" || error_exit "Falha ao copiar 3proxy"
    chmod +x "$PREFIX/bin/3proxy"
}

configure_3proxy() {
    log "${YELLOW}[*] Configurando 3proxy...${NC}"
    mkdir -p "$PREFIX/etc/3proxy"

    # Perguntar sobre limitar conexões
    log "${YELLOW}[?] Deseja limitar o número máximo de conexões simultâneas no 3proxy? [s/n]${NC}"
    read -r limitar_conexoes

    if [[ "${limitar_conexoes,,}" == "s" || "${limitar_conexoes,,}" == "sim" ]]; then
        log "${YELLOW}[*] Digite o número máximo de conexões permitidas (ex: 100):${NC}"
        read -r max_conexoes
        if [[ ! "$max_conexoes" =~ ^[0-9]+$ || "$max_conexoes" -lt 1 ]]; then
            error_exit "Número de conexões inválido. Deve ser um número maior que zero."
        fi
        MAXCONN_LINE="maxconn $max_conexoes"
    else
        MAXCONN_LINE=""
    fi

    cat > "$PROXY_CFG" <<EOF
log $LOG_DIR/3proxy.log D
logformat "%d.%m.%Y %H:%M:%S %N %U %C:%c %R:%r %I %O %h"
nscache 65536
nserver ${DNS_SERVERS// / nserver }
timeouts 1 5 30 60 180 1800 15 60
auth none
allow *
$MAXCONN_LINE
proxy -n -a -p$PROXY_PORT -i0.0.0.0 -e0.0.0.0
flush
EOF

    chmod 600 "$PROXY_CFG"
    echo -e "${DNS_SERVERS// /\n}" > "$PREFIX/etc/resolv.conf"
    chmod 444 "$PREFIX/etc/resolv.conf"
}

install_frp() {
    log "${YELLOW}[*] Instalando módulo de tráfego Flux (FRP)...${NC}"
    cd ~ && rm -rf frp
    git clone https://github.com/fatedier/frp || error_exit "Falha ao clonar FRP"
    cd ~/frp/cmd/frpc
    go build || error_exit "Falha ao compilar FRP"
    mkdir -p "$FRP_DIR"
    cp ./frpc "$FRP_DIR/flux" || error_exit "Falha ao copiar FRP"
    chmod +x "$FRP_DIR/flux"
}

configure_frp() {
    log "${YELLOW}[*] Configurando FRP...${NC}"
    RANDOM_NAME="ep-$(head /dev/urandom | tr -dc a-z0-9 | head -c6)"
    RANDOM_PORT=$((RANDOM % 40000 + 10000))
    cat > "$FRP_INI" <<EOF
[common]
server_addr = $FRP_SERVER_ADDR
server_port = $FRP_SERVER_PORT
log_file = $LOG_DIR/flux.log
log_level = $LOG_LEVEL

[$RANDOM_NAME]
type = tcp
local_ip = 127.0.0.1
local_port = $PROXY_PORT
remote_port = $RANDOM_PORT
EOF
    chmod 600 "$FRP_INI"
    echo "SESSÃO = $RANDOM_NAME" > "$FRP_DIR/INFO.txt"
    echo "PORTA REMOTA = $RANDOM_PORT" >> "$FRP_DIR/INFO.txt"
}

setup_autostart() {
    log "${YELLOW}[*] Configurando inicialização automática...${NC}"
    mkdir -p "$HOME/.termux/boot"
    cat > "$BOOT_SCRIPT" <<EOF
#!/data/data/com.termux/files/usr/bin/bash
termux-wake-lock
sleep 3
nohup env LD_LIBRARY_PATH=$PREFIX/lib $PREFIX/bin/3proxy $PROXY_CFG > $LOG_DIR/proxy_server.log 2>&1 &
nohup $FRP_DIR/flux -c $FRP_INI > $LOG_DIR/flux.log 2>&1 &
EOF
    chmod +x "$BOOT_SCRIPT"
}

start_services() {
    log "${YELLOW}[*] Iniciando 3proxy e FRP...${NC}"
    pkill -f 3proxy || true
    pkill -f frpc || true
    nohup env LD_LIBRARY_PATH=$PREFIX/lib "$PREFIX/bin/3proxy" "$PROXY_CFG" > "$LOG_DIR/proxy_server.log" 2>&1 &
    nohup "$FRP_DIR/flux" -c "$FRP_INI" > "$LOG_DIR/flux.log" 2>&1 &
    sleep 2
    if ! pgrep -f 3proxy >/dev/null || ! pgrep -f frpc >/dev/null; then
        error_exit "Falha ao iniciar serviços. Verifique os logs em $LOG_DIR"
    fi
}

display_results() {
    IP=$(ifconfig 2>/dev/null | grep -E 'inet (192|10|172)' | awk '{print $2}' | head -n1 || echo "Não detectado")
    log ""
    log "========================================"
    log "${GREEN}✅ $SCRIPT_NAME v$VERSION ativado com sucesso!${NC}"
    log "----------------------------------------"
    log "IP local: $IP"
    log "Porta de acesso: $PROXY_PORT"
    log "Canal Flux: $RANDOM_NAME"
    log "Porta Remota: $RANDOM_PORT"
    log "Log 3proxy: $LOG_DIR/proxy_server.log"
    log "Log FRP: $LOG_DIR/flux.log"
    log "Configuração: $CONFIG_FILE"
    log "----------------------------------------"
    log "${YELLOW}[!] Para inicialização automática, instale o Termux:Boot:${NC}"
    log "    https://f-droid.org/packages/com.termux.boot"
    log "${YELLOW}[!] Reinicie o celular após instalar o app.${NC}"
    log "========================================"
}

main() {
    log "========================================"
    log "${YELLOW}[*] $SCRIPT_NAME v$VERSION${NC}"
    log "========================================"
    check_termux
    load_config
    prompt_frp_port
    install_dependencies
    install_3proxy
    configure_3proxy
    install_frp
    configure_frp
    setup_autostart
    start_services
    display_results
}

main

