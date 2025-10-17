# Guía de Instalación - Red Recognition

## 🚀 Instalación Rápida (Linux/Kali)

### Método 1: Script Automático

```bash
# Clonar o descargar el proyecto
cd RedRecognition

# Ejecutar script de instalación
sudo bash setup.sh

# Configurar variables
nano config.env

# Ejecutar
sudo python3 main.py
```

### Método 2: Manual

```bash
# 1. Instalar dependencias del sistema
sudo apt-get update
sudo apt-get install -y python3 python3-pip nmap curl dnsutils ffmpeg libopencv-dev

# 2. Instalar dependencias de Python
pip3 install -r requirements.txt

# 3. Copiar configuración
cp config.env.example config.env

# 4. Editar configuración
nano config.env

# 5. Crear directorios
mkdir -p reports loot/stolen_videos loot/router_configs loot/credentials loot/backdoors harvested_files

# 6. Ejecutar
sudo python3 main.py
```

## 📝 Configuración Obligatoria

Edita `config.env` y configura al menos estos valores:

```ini
# IMPORTANTE: Tu servidor C2
C2_SERVER_URL=http://TU_IP:8000

# IMPORTANTE: Tu identificador
C2_IDENTIFIER=TU_NOMBRE_PROYECTO
```

## 🖥️ Servidor C2 Simple

Crea un servidor simple para recibir IPs de backdoors:

```python
# c2_server.py
from flask import Flask, request
from datetime import datetime

app = Flask(__name__)

@app.route('/')
def receive():
    ip = request.args.get('ip', 'unknown')
    timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    
    print(f"[{timestamp}] Compromised IP: {ip}")
    
    with open('compromised.log', 'a') as f:
        f.write(f"[{timestamp}] {ip}\n")
    
    return 'OK', 200

if __name__ == '__main__':
    # Instalar primero: pip install flask
    app.run(host='0.0.0.0', port=8000)
```

Ejecutar:
```bash
pip install flask
python3 c2_server.py
```

## 🔍 Verificación de Instalación

```bash
# Verificar Python
python3 --version

# Verificar módulos críticos
python3 -c "import scapy, nmap, requests, paramiko, cv2"

# Si todo está bien, no debería mostrar errores
```

## 🐛 Solución de Problemas

### Error: ModuleNotFoundError

```bash
# Reinstalar dependencias
pip3 install -r requirements.txt --force-reinstall --user
```

### Error: Permission denied

```bash
# Asegúrate de ejecutar con sudo
sudo python3 main.py
```

### Error: OpenCV no funciona

```bash
# Instalar dependencias de OpenCV
sudo apt-get install -y libopencv-dev python3-opencv ffmpeg
pip3 install opencv-python opencv-contrib-python --force-reinstall
```

### Error: nmap no funciona

```bash
# Instalar nmap y python-nmap
sudo apt-get install -y nmap
pip3 install python-nmap --force-reinstall
```

## 📦 Dependencias Completas

### Sistema:
- Python 3.8+
- nmap
- curl
- dnsutils (dig)
- ffmpeg
- libopencv-dev

### Python:
- scapy
- python-nmap
- netifaces
- requests
- pysmb
- paramiko
- fabric
- opencv-python
- opencv-contrib-python
- beautifulsoup4
- lxml
- impacket
- pwntools
- jinja2
- python-dotenv
- colorama
- tqdm

## 🎯 Primera Ejecución

1. **Asegúrate de tener autorización**
2. **Configura config.env**
3. **Ejecuta:**

```bash
sudo python3 main.py
```

4. **Selecciona modo de ejecución**
5. **Revisa informes en:**
   - `reports/INFORME_EJECUTIVO.html` (abrir en navegador)
   - `reports/INFORME_GENERAL_PENTESTING.json` (técnico)

## 📂 Ubicación de Archivos Importantes

```
RedRecognition/
├── config.env                          # TU CONFIGURACIÓN (no subir a git)
├── main.py                             # Ejecutar este archivo
├── reports/
│   └── INFORME_EJECUTIVO.html          # ⭐ ABRIR EN NAVEGADOR
├── loot/
│   ├── stolen_videos/                  # Videos capturados
│   ├── credentials/
│   │   └── credentials_found.json      # ⭐ CREDENCIALES OBTENIDAS
│   └── backdoors/
│       └── access_instructions.txt     # ⭐ COMO ACCEDER A BACKDOORS
```

## ⚠️ Importante

- **NO SUBAS** `config.env` a repositorios públicos
- **GUARDA** las credenciales encontradas de forma segura
- **ELIMINA** los backdoors después de la prueba
- **DOCUMENTA** todo para el cliente

## 🔒 Seguridad

Este archivo contiene configuraciones sensibles:
```
config.env
```

Asegúrate de que:
- Tiene permisos restrictivos: `chmod 600 config.env`
- Está en `.gitignore`
- No se comparte públicamente

## 📞 Soporte

Si encuentras problemas:

1. Verifica que todas las dependencias estén instaladas
2. Asegúrate de tener privilegios de root
3. Revisa los logs en `reports/`
4. Verifica la configuración en `config.env`

---

**¡Listo para pentesting!** 🎯

