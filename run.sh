#!/bin/bash
# Script para ejecutar Red Recognition en Kali Linux con venv

# Obtener el directorio del script
SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"

# Verificar que el venv existe
if [ ! -d "$SCRIPT_DIR/red" ]; then
    echo "[!] Entorno virtual 'red' no encontrado"
    echo "[*] Creando entorno virtual..."
    python3 -m venv red
    echo "[✓] Entorno virtual creado"
fi

# Activar el entorno virtual
source "$SCRIPT_DIR/red/bin/activate"

# Verificar si las dependencias están instaladas
if ! python3 -c "import scapy, nmap, requests" 2>/dev/null; then
    echo "[*] Instalando dependencias en el entorno virtual..."
    pip install -r requirements.txt
fi

# Ejecutar con sudo manteniendo el venv
echo "[*] Ejecutando Red Recognition..."
sudo "$SCRIPT_DIR/red/bin/python3" "$SCRIPT_DIR/main.py" "$@"

