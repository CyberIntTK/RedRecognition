# Red Recognition - Reconocimiento de Red WiFi y Descarga de Archivos

Script modular de Python para reconocimiento automático de redes WiFi y descarga de archivos compartidos. Diseñado para pentesting y auditorías de seguridad en Kali Linux.

## 🎯 Características

### Módulo 1: Reconocimiento de Red
- ✅ **Auto-detección de red WiFi** - Detecta automáticamente SSID, canal, frecuencia, señal, IP, gateway y rango de red
- ✅ **Descubrimiento de hosts** - Escaneo ARP para identificar todos los dispositivos conectados
- ✅ **Escaneo de puertos** - Detecta puertos abiertos (top 1000 o top 100 en modo rápido)
- ✅ **Identificación de servicios** - Detecta servicios, versiones y sistemas operativos
- ✅ **Guardado incremental** - Los datos se guardan continuamente (no se pierden si se interrumpe)
- ✅ **IP pública y geolocalización** - Obtiene tu IP pública, ISP y ubicación

### Módulo 2: Descarga de Archivos Compartidos
- ✅ **Recursos compartidos SMB/SAMBA** - Intenta acceso anónimo y descarga archivos
- ✅ **Servidores FTP** - Verifica acceso FTP anónimo y descarga archivos
- ✅ **Directorios HTTP** - Detecta directorios web accesibles públicamente
- ✅ **Descarga inteligente** - Limita tamaño de archivos y cantidad por host
- ✅ **Organización automática** - Archivos organizados por IP/Servicio
- ✅ **Guardado incremental** - Metadata guardada continuamente

## 📋 Requisitos

- Kali Linux
- Python 3.7+
- Nmap
- Permisos de root

## 🚀 Instalación

```bash
# Instalar dependencias del sistema
sudo apt-get update
sudo apt-get install -y python3 python3-pip nmap wireless-tools network-manager

# Instalar dependencias de Python
sudo pip3 install -r requirements.txt
```

## 💻 Uso

### Conectarse a WiFi primero

```bash
# Ver redes disponibles
sudo nmcli device wifi list

# Conectarse
sudo nmcli device wifi connect "NOMBRE_RED" password "CONTRASEÑA"
```

### Módulo 1: Reconocimiento de Red

```bash
# Ver información de WiFi (sin escanear)
sudo python3 main.py --show-wifi-only

# Escaneo completo (15-30 min) - MÓDULO 1 por defecto
sudo python3 main.py

# O explícitamente
sudo python3 main.py -m 1

# Escaneo rápido (5-10 min)
sudo python3 main.py --quick

# Solo descubrir hosts (1-2 min)
sudo python3 main.py --no-port-scan

# Archivo de salida personalizado
sudo python3 main.py -o mi_escaneo.json

# Especificar interfaz manualmente
sudo python3 main.py -i wlan0
```

### Módulo 2: Descarga de Archivos Compartidos

```bash
# Ejecutar módulo 2 (usa reconocimiento.json por defecto)
sudo python3 main.py -m 2

# Usar archivo de reconocimiento personalizado
sudo python3 main.py -m 2 --recon-file mi_escaneo.json

# Limitar tamaño máximo de archivos (en MB)
sudo python3 main.py -m 2 --max-file-size 50

# Limitar cantidad de archivos por host
sudo python3 main.py -m 2 --max-files 50

# Combinación de opciones
sudo python3 main.py -m 2 --max-file-size 20 --max-files 200
```

### Flujo de trabajo completo

```bash
# 1. Reconocimiento de red
sudo python3 main.py

# 2. Descarga de archivos compartidos
sudo python3 main.py -m 2

# Ver ayuda
python3 main.py --help
```

## 📊 Salida

### Módulo 1: Reconocimiento

El Módulo 1 genera un archivo JSON (`reconocimiento.json` por defecto) con:

### Información de WiFi detectada automáticamente
```json
{
  "wifi_connection": {
    "interface": "wlan0",
    "ssid": "MiRed-WiFi",
    "bssid": "AA:BB:CC:DD:EE:FF",
    "frequency": "2.437 GHz",
    "channel": "6",
    "signal_quality": "75%",
    "signal_level": "-45 dBm",
    "ip_address": "192.168.1.100",
    "gateway": "192.168.1.1",
    "network_range": "192.168.1.0/24"
  }
}
```

### Hosts descubiertos
```json
{
  "discovered_hosts": [
    {
      "ip": "192.168.1.1",
      "mac": "AA:BB:CC:DD:EE:FF",
      "vendor": "TP-Link Technologies",
      "hostname": "router.home",
      "ports": [
        {
          "port": 22,
          "protocol": "tcp",
          "state": "open",
          "service": "ssh",
          "product": "OpenSSH",
          "version": "8.4p1"
        }
      ],
      "services": {...},
      "os_detection": {...}
    }
  ]
}
```

### Resumen del escaneo
```json
{
  "scan_summary": {
    "scan_duration_seconds": 287.45,
    "total_hosts_discovered": 4,
    "total_open_ports": 12,
    "network_range_scanned": "192.168.1.0/24"
  }
}
```

### Módulo 2: Archivos Descargados

El Módulo 2 genera:
- **Directorio `harvested_files/`** con archivos descargados organizados por IP y servicio
- **Archivo `archivos_descargados.json`** con metadata

Estructura de directorios:
```
harvested_files/
├── 192.168.1.1/
│   ├── SMB/
│   │   └── SharedDocs/
│   │       ├── documento1.pdf
│   │       └── archivo.txt
│   └── FTP/
│       └── backup.zip
└── 192.168.1.10/
    └── SMB/
        └── Public/
            └── readme.txt
```

Contenido del JSON:
```json
{
  "timestamp": "2025-10-16T...",
  "hosts_analyzed": [
    {
      "ip": "192.168.1.1",
      "hostname": "server.local",
      "services_checked": ["SMB", "FTP"],
      "shares_found": [
        {
          "type": "SMB",
          "name": "SharedDocs",
          "path": "\\\\192.168.1.1\\SharedDocs",
          "accessible": true,
          "files": [...]
        }
      ],
      "files_downloaded": [
        {
          "filename": "documento1.pdf",
          "size": 524288,
          "share": "SharedDocs",
          "local_path": "harvested_files/192.168.1.1/SMB/SharedDocs/documento1.pdf",
          "downloaded_at": "2025-10-16T..."
        }
      ]
    }
  ],
  "statistics": {
    "total_hosts": 4,
    "hosts_with_shares": 2,
    "smb_shares_found": 3,
    "ftp_accessible": 1,
    "total_files_downloaded": 15,
    "total_size_bytes": 15728640,
    "failed_downloads": 2
  }
}
```

## 🔧 Auto-configuración

El script detecta automáticamente la red WiFi usando tres métodos (en orden):

1. **nmcli** (Network Manager) - método preferido
2. **iwconfig** (Wireless Tools) - fallback
3. **Búsqueda manual** - último recurso (interfaces wlan*, wlp*)

No necesitas especificar la interfaz ni el rango de red manualmente.

## 🛠️ Solución de problemas

### "No se detectó conexión WiFi"
```bash
# Verificar conexión
nmcli device status
iwconfig

# Reconectar
sudo nmcli device wifi connect "SSID" password "PASSWORD"
```

### "Permission denied"
```bash
# Siempre ejecutar con sudo
sudo python3 main.py
```

### "Module not found"
```bash
# Reinstalar dependencias
sudo pip3 install -r requirements.txt
```

### No encuentra dispositivos
```bash
# Verificar conectividad al gateway
ping $(ip route | grep default | awk '{print $3}')

# Ver info de WiFi para diagnosticar
sudo python3 main.py --show-wifi-only
```

## 🔒 Arquitectura Modular

```
RedRecognition/
├── main.py                      # Script principal
├── modules/
│   ├── __init__.py
│   ├── network_recon.py         # Módulo 1: Reconocimiento
│   └── file_harvester.py        # Módulo 2: Descarga de archivos
├── requirements.txt             # Dependencias
├── README.md                    # Este archivo
├── reconocimiento.json          # Salida Módulo 1 (generado)
├── archivos_descargados.json    # Salida Módulo 2 (generado)
└── harvested_files/             # Archivos descargados (generado)
```

### Módulos futuros planificados
- Módulo 3: Análisis de vulnerabilidades
- Módulo 4: Exploración web avanzada
- Módulo 5: Reportes en PDF/HTML

## ⚠️ Advertencia Legal

**IMPORTANTE:** Esta herramienta es solo para uso autorizado.

✅ **Permitido:**
- Tu propia red doméstica
- Redes con autorización escrita del propietario
- Laboratorios de pentesting autorizados
- Entornos educativos

❌ **Prohibido:**
- Redes públicas sin autorización
- Redes de terceros
- Cualquier red sin permiso explícito

El uso no autorizado puede ser **ilegal** y resultar en consecuencias legales graves.

## 📝 Notas Técnicas

### Dependencias de Python

**Módulo 1:**
- `scapy` - Escaneo ARP de red
- `python-nmap` - Escaneo de puertos y servicios
- `netifaces` - Información de interfaces de red
- `requests` - Obtención de IP pública

**Módulo 2:**
- `pysmb` - Acceso a recursos compartidos SMB/SAMBA
- `requests` - Descarga HTTP
- `ftplib` - Acceso FTP (librería estándar)

### Guardado incremental
El script guarda los resultados después de cada descubrimiento importante:
- Después de detectar WiFi
- Después de cada host encontrado
- Después de escanear cada host

Si se interrumpe (Ctrl+C), los datos parciales están guardados.

### Métodos de detección WiFi

**nmcli (preferido):**
```bash
nmcli -t -f DEVICE,TYPE,STATE device
nmcli -t -f SSID,BSSID,FREQ,CHAN,SIGNAL device wifi list
```

**iwconfig (fallback):**
```bash
iwconfig
# Extrae SSID, BSSID, frecuencia, calidad de señal
```

**Manual (último recurso):**
```bash
# Busca interfaces: wlan*, wlp*, wlo*, wl*
# Verifica que tenga IP asignada
```

## 🎓 Ejemplos de uso

### Auditoría completa (Módulo 1 + 2)
```bash
# Paso 1: Reconocimiento
sudo python3 main.py -o auditoria_casa.json

# Paso 2: Descarga de archivos
sudo python3 main.py -m 2 --recon-file auditoria_casa.json
```

### Pentesting rápido
```bash
# Reconocimiento rápido
sudo python3 main.py --quick -o pentest.json

# Descarga limitada de archivos
sudo python3 main.py -m 2 --recon-file pentest.json --max-file-size 5 --max-files 50
```

### Inventario de red
```bash
# Solo hosts (sin puertos)
sudo python3 main.py --no-port-scan -o inventario.json
```

### Escaneos con timestamp
```bash
# Reconocimiento con fecha
FECHA=$(date +%Y%m%d_%H%M%S)
sudo python3 main.py -o "scan_${FECHA}.json"

# Descarga de archivos
sudo python3 main.py -m 2 --recon-file "scan_${FECHA}.json"
```

### Análisis de resultados

**Módulo 1:**
```bash
# Ver solo IPs encontradas
cat reconocimiento.json | jq -r '.discovered_hosts[].ip'

# Contar hosts descubiertos
cat reconocimiento.json | jq '.discovered_hosts | length'

# Ver puertos abiertos por host
cat reconocimiento.json | jq '.discovered_hosts[] | {ip: .ip, ports: [.ports[].port]}'
```

**Módulo 2:**
```bash
# Ver archivos descargados
cat archivos_descargados.json | jq '.files_downloaded[].filename'

# Contar archivos por host
cat archivos_descargados.json | jq '.hosts_analyzed[] | {ip: .ip, count: (.files_downloaded | length)}'

# Ver estadísticas
cat archivos_descargados.json | jq '.statistics'

# Listar archivos descargados físicamente
find harvested_files/ -type f
```

## 🚦 Flujo de Ejecución

### Módulo 1: Reconocimiento
1. Verifica permisos de root
2. Detecta automáticamente la conexión WiFi
3. Muestra toda la información de la red
4. Pide confirmación para continuar
5. Escanea la red buscando hosts (ARP)
6. Escanea puertos en cada host (Nmap)
7. Identifica servicios y versiones
8. Guarda todo en JSON

### Módulo 2: Descarga de Archivos
1. Lee el archivo de reconocimiento del Módulo 1
2. Identifica hosts con servicios de archivos (SMB, FTP, HTTP)
3. Para cada host:
   - Intenta acceso anónimo a SMB/SAMBA
   - Intenta acceso FTP anónimo
   - Verifica directorios HTTP comunes
4. Descarga archivos accesibles (respetando límites)
5. Organiza archivos por host/servicio
6. Guarda metadata en JSON

## 📞 Soporte

Si encuentras problemas:

1. Verifica que estés conectado a WiFi: `nmcli device status`
2. Ejecuta con sudo: `sudo python3 main.py`
3. Prueba la detección: `sudo python3 main.py --show-wifi-only`
4. Verifica dependencias: `pip3 list | grep -E "(scapy|nmap|netifaces|requests)"`

---

**Desarrollado para auditorías de seguridad en Kali Linux** 🐧🛡️
