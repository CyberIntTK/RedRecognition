# Red Recognition - Reconocimiento de Red WiFi

Script de Python para reconocimiento automático de redes WiFi. Diseñado para pentesting y auditorías de seguridad en Kali Linux.

## 🎯 Características

- ✅ **Auto-detección de red WiFi** - Detecta automáticamente SSID, canal, frecuencia, señal, IP, gateway y rango de red
- ✅ **Descubrimiento de hosts** - Escaneo ARP para identificar todos los dispositivos conectados
- ✅ **Escaneo de puertos** - Detecta puertos abiertos (top 1000 o top 100 en modo rápido)
- ✅ **Identificación de servicios** - Detecta servicios, versiones y sistemas operativos
- ✅ **Guardado incremental** - Los datos se guardan continuamente (no se pierden si se interrumpe)
- ✅ **IP pública y geolocalización** - Obtiene tu IP pública, ISP y ubicación

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

### Comandos principales

```bash
# Ver información de WiFi (sin escanear)
sudo python3 main.py --show-wifi-only

# Escaneo completo (15-30 min)
sudo python3 main.py

# Escaneo rápido (5-10 min)
sudo python3 main.py --quick

# Solo descubrir hosts (1-2 min)
sudo python3 main.py --no-port-scan

# Archivo de salida personalizado
sudo python3 main.py -o mi_escaneo.json

# Especificar interfaz manualmente
sudo python3 main.py -i wlan0

# Ver ayuda
python3 main.py --help
```

## 📊 Salida

El script genera un archivo JSON (`reconocimiento.json` por defecto) con:

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
├── main.py                  # Script principal
├── modules/
│   ├── __init__.py
│   └── network_recon.py     # Módulo de reconocimiento
├── requirements.txt         # Dependencias
└── README.md               # Este archivo
```

### Módulos futuros planificados
- Módulo 2: Análisis de vulnerabilidades
- Módulo 3: Exploración web
- Módulo 4: Reportes en PDF/HTML

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
- `scapy` - Escaneo ARP de red
- `python-nmap` - Escaneo de puertos y servicios
- `netifaces` - Información de interfaces de red
- `requests` - Obtención de IP pública

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

### Auditoría doméstica
```bash
sudo python3 main.py -o auditoria_casa.json
```

### Pentesting rápido
```bash
sudo python3 main.py --quick -o pentest.json
```

### Inventario de red
```bash
sudo python3 main.py --no-port-scan -o inventario.json
```

### Escaneos con timestamp
```bash
sudo python3 main.py -o "scan_$(date +%Y%m%d_%H%M%S).json"
```

### Ver solo IPs encontradas
```bash
cat reconocimiento.json | jq -r '.discovered_hosts[].ip'
```

### Contar hosts descubiertos
```bash
cat reconocimiento.json | jq '.discovered_hosts | length'
```

## 🚦 Flujo de Ejecución

1. Verifica permisos de root
2. Detecta automáticamente la conexión WiFi
3. Muestra toda la información de la red
4. Pide confirmación para continuar
5. Escanea la red buscando hosts (ARP)
6. Escanea puertos en cada host (Nmap)
7. Identifica servicios y versiones
8. Guarda todo en JSON

## 📞 Soporte

Si encuentras problemas:

1. Verifica que estés conectado a WiFi: `nmcli device status`
2. Ejecuta con sudo: `sudo python3 main.py`
3. Prueba la detección: `sudo python3 main.py --show-wifi-only`
4. Verifica dependencias: `pip3 list | grep -E "(scapy|nmap|netifaces|requests)"`

---

**Desarrollado para auditorías de seguridad en Kali Linux** 🐧🛡️
