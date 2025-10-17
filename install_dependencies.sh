#!/bin/bash
# ============================================================================
# RED RECOGNITION - INSTALADOR DE DEPENDENCIAS
# Instala todas las dependencias necesarias para el sistema
# ============================================================================

echo "╔═══════════════════════════════════════════════════════════╗"
echo "║     RED RECOGNITION - INSTALADOR DE DEPENDENCIAS         ║"
echo "╚═══════════════════════════════════════════════════════════╝"
echo ""

# Colores
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# 1. Instalar dependencias del sistema
echo -e "${YELLOW}[*]${NC} Instalando dependencias del sistema..."
sudo apt-get update -qq
sudo apt-get install -y \
    python3 \
    python3-pip \
    python3-dev \
    nmap \
    curl \
    dnsutils \
    ffmpeg \
    libopencv-dev \
    libxml2-dev \
    libxslt1-dev \
    libssl-dev \
    libffi-dev \
    libcurl4-openssl-dev \
    build-essential \
    python3-lxml \
    2>/dev/null

if [ $? -eq 0 ]; then
    echo -e "${GREEN}[✓]${NC} Dependencias del sistema instaladas"
else
    echo -e "${RED}[!]${NC} Error instalando dependencias del sistema"
    exit 1
fi

# 2. Actualizar pip
echo -e "${YELLOW}[*]${NC} Actualizando pip..."
pip3 install --upgrade pip setuptools wheel -q

# 3. Instalar dependencias de Python (por grupos para mejor control)
echo -e "${YELLOW}[*]${NC} Instalando dependencias de Python..."

# Grupo 1: Networking (CRÍTICO)
echo -e "${YELLOW}    [*]${NC} Grupo 1: Networking..."
pip3 install scapy python-nmap netifaces requests urllib3 -q
if [ $? -eq 0 ]; then
    echo -e "${GREEN}    [✓]${NC} Networking instalado"
fi

# Grupo 2: SSH y Remote Access
echo -e "${YELLOW}    [*]${NC} Grupo 2: SSH y Remote Access..."
pip3 install paramiko fabric -q
if [ $? -eq 0 ]; then
    echo -e "${GREEN}    [✓]${NC} SSH instalado"
fi

# Grupo 3: File Sharing
echo -e "${YELLOW}    [*]${NC} Grupo 3: File Sharing..."
pip3 install pysmb -q
if [ $? -eq 0 ]; then
    echo -e "${GREEN}    [✓]${NC} File Sharing instalado"
fi

# Grupo 4: Video (IMPORTANTE)
echo -e "${YELLOW}    [*]${NC} Grupo 4: Video Capture..."
pip3 install opencv-python opencv-contrib-python -q
if [ $? -eq 0 ]; then
    echo -e "${GREEN}    [✓]${NC} Video instalado"
else
    echo -e "${YELLOW}    [!]${NC} OpenCV puede tener problemas, continuando..."
fi

# Grupo 5: Web Exploitation
echo -e "${YELLOW}    [*]${NC} Grupo 5: Web Exploitation..."
pip3 install beautifulsoup4 -q
# lxml desde sistema ya está instalado
if [ $? -eq 0 ]; then
    echo -e "${GREEN}    [✓]${NC} Web Exploitation instalado"
fi

# Grupo 6: Advanced Tools (opcionales)
echo -e "${YELLOW}    [*]${NC} Grupo 6: Advanced Tools..."
pip3 install impacket pwntools -q 2>/dev/null
if [ $? -eq 0 ]; then
    echo -e "${GREEN}    [✓]${NC} Advanced Tools instalado"
else
    echo -e "${YELLOW}    [!]${NC} Algunas herramientas avanzadas no se instalaron (opcional)"
fi

# Grupo 7: Reporting
echo -e "${YELLOW}    [*]${NC} Grupo 7: Reporting..."
pip3 install jinja2 markdown -q
if [ $? -eq 0 ]; then
    echo -e "${GREEN}    [✓]${NC} Reporting instalado"
fi

# Grupo 8: Utilidades
echo -e "${YELLOW}    [*]${NC} Grupo 8: Utilidades..."
pip3 install python-dotenv colorama tqdm python-dateutil psutil -q
if [ $? -eq 0 ]; then
    echo -e "${GREEN}    [✓]${NC} Utilidades instaladas"
fi

# Grupo 9: pycurl (puede fallar, no crítico)
echo -e "${YELLOW}    [*]${NC} Grupo 9: pycurl (opcional)..."
pip3 install pycurl -q 2>/dev/null
if [ $? -eq 0 ]; then
    echo -e "${GREEN}    [✓]${NC} pycurl instalado"
else
    echo -e "${YELLOW}    [!]${NC} pycurl no instalado (opcional, puede funcionar sin él)"
fi

echo ""
echo "═══════════════════════════════════════════════════════════"
echo "  VERIFICACIÓN DE INSTALACIÓN"
echo "═══════════════════════════════════════════════════════════"
echo ""

# Verificar módulos críticos
echo -e "${YELLOW}[*]${NC} Verificando módulos críticos..."

critical_modules=("scapy" "nmap" "requests" "paramiko" "cv2" "bs4" "jinja2")
all_ok=true

for module in "${critical_modules[@]}"; do
    if python3 -c "import $module" 2>/dev/null; then
        echo -e "${GREEN}  [✓]${NC} $module"
    else
        echo -e "${RED}  [✗]${NC} $module - FALTA"
        all_ok=false
    fi
done

echo ""

if [ "$all_ok" = true ]; then
    echo "═══════════════════════════════════════════════════════════"
    echo -e "${GREEN}  ✓ INSTALACIÓN COMPLETADA EXITOSAMENTE${NC}"
    echo "═══════════════════════════════════════════════════════════"
    echo ""
    echo "El sistema está listo para usar."
    echo ""
    echo "Ejecutar:"
    echo "  sudo python3 main.py"
    echo ""
else
    echo "═══════════════════════════════════════════════════════════"
    echo -e "${YELLOW}  ⚠ INSTALACIÓN COMPLETADA CON ADVERTENCIAS${NC}"
    echo "═══════════════════════════════════════════════════════════"
    echo ""
    echo "Algunos módulos opcionales no se instalaron."
    echo "El sistema debería funcionar, pero algunos módulos pueden fallar."
    echo ""
    echo "Intentar reinstalar manualmente los módulos faltantes."
    echo ""
fi

echo "═══════════════════════════════════════════════════════════"

