#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Módulo 2: File Harvester (Recolector de Archivos)
Descarga archivos compartidos accesibles en la red desde SMB, FTP, NFS y HTTP
"""

import json
import os
import socket
import threading
from datetime import datetime
from typing import Dict, List, Optional
import ftplib
import urllib.request
import urllib.parse
from pathlib import Path

# Importaciones opcionales según disponibilidad
try:
    from smb.SMBConnection import SMBConnection
    from smb import smb_structs
    SMB_AVAILABLE = True
except ImportError:
    SMB_AVAILABLE = False

try:
    import requests
    REQUESTS_AVAILABLE = True
except ImportError:
    REQUESTS_AVAILABLE = False


class FileHarvester:
    """Clase para recolectar archivos compartidos en la red"""
    
    def __init__(self, reconnaissance_file: str = "reconocimiento.json",
                 output_dir: str = "harvested_files",
                 output_json: str = "archivos_descargados.json"):
        """
        Inicializa el módulo de recolección de archivos
        
        Args:
            reconnaissance_file: Archivo JSON del reconocimiento (Módulo 1)
            output_dir: Directorio donde guardar archivos descargados
            output_json: Archivo JSON con metadata de archivos descargados
        """
        self.reconnaissance_file = reconnaissance_file
        self.output_dir = output_dir
        self.output_json = output_json
        self.lock = threading.Lock()
        
        # Crear directorio de salida
        Path(self.output_dir).mkdir(parents=True, exist_ok=True)
        
        # Estructura de resultados
        self.results = {
            "timestamp": datetime.now().isoformat(),
            "reconnaissance_file": reconnaissance_file,
            "output_directory": output_dir,
            "hosts_analyzed": [],
            "files_downloaded": [],
            "statistics": {
                "total_hosts": 0,
                "hosts_with_shares": 0,
                "smb_shares_found": 0,
                "ftp_accessible": 0,
                "http_directories_found": 0,
                "total_files_downloaded": 0,
                "total_size_bytes": 0,
                "failed_downloads": 0
            }
        }
        
        # Guardar estructura inicial
        self._save_results()
    
    def _save_results(self):
        """Guarda los resultados en JSON de forma segura"""
        with self.lock:
            try:
                with open(self.output_json, 'w', encoding='utf-8') as f:
                    json.dump(self.results, f, indent=4, ensure_ascii=False)
            except Exception as e:
                print(f"[!] Error guardando resultados: {str(e)}")
    
    def load_reconnaissance(self) -> Dict:
        """Carga el archivo de reconocimiento del Módulo 1"""
        try:
            with open(self.reconnaissance_file, 'r', encoding='utf-8') as f:
                return json.load(f)
        except FileNotFoundError:
            print(f"[!] Error: No se encuentra el archivo {self.reconnaissance_file}")
            print(f"[!] Primero ejecuta el Módulo 1: sudo python3 main.py")
            return None
        except json.JSONDecodeError:
            print(f"[!] Error: El archivo {self.reconnaissance_file} no es un JSON válido")
            return None
    
    def run_harvesting(self, max_file_size: int = 10485760, max_files_per_host: int = 100):
        """
        Ejecuta la recolección de archivos
        
        Args:
            max_file_size: Tamaño máximo de archivo a descargar (bytes, default 10MB)
            max_files_per_host: Máximo de archivos por host (default 100)
        """
        print("[*] Iniciando Módulo 2: File Harvester")
        print(f"[*] Leyendo archivo de reconocimiento: {self.reconnaissance_file}\n")
        
        # Cargar datos del reconocimiento
        recon_data = self.load_reconnaissance()
        if not recon_data:
            return
        
        # Obtener hosts descubiertos
        discovered_hosts = recon_data.get('discovered_hosts', [])
        if not discovered_hosts:
            print("[!] No se encontraron hosts en el reconocimiento")
            return
        
        print(f"[*] Hosts a analizar: {len(discovered_hosts)}")
        self.results['statistics']['total_hosts'] = len(discovered_hosts)
        self._save_results()
        
        # Analizar cada host
        for idx, host in enumerate(discovered_hosts):
            print(f"\n[*] Analizando host {idx+1}/{len(discovered_hosts)}: {host['ip']}")
            
            host_result = {
                "ip": host['ip'],
                "hostname": host.get('hostname', 'Unknown'),
                "mac": host.get('mac', 'Unknown'),
                "services_checked": [],
                "shares_found": [],
                "files_downloaded": []
            }
            
            # Verificar servicios de archivos compartidos
            ports = host.get('ports', [])
            
            # SMB/SAMBA (puertos 139, 445)
            if any(p.get('port') in [139, 445] for p in ports):
                print(f"    [*] Detectado SMB/SAMBA en {host['ip']}")
                self._check_smb_shares(host['ip'], host_result, max_file_size, max_files_per_host)
            
            # FTP (puerto 21)
            if any(p.get('port') == 21 for p in ports):
                print(f"    [*] Detectado FTP en {host['ip']}")
                self._check_ftp_access(host['ip'], host_result, max_file_size, max_files_per_host)
            
            # HTTP/HTTPS (puertos 80, 443, 8080)
            if any(p.get('port') in [80, 443, 8080] for p in ports):
                print(f"    [*] Detectado HTTP en {host['ip']}")
                self._check_http_directories(host['ip'], host_result, ports, max_file_size, max_files_per_host)
            
            # Guardar resultado del host
            if host_result['shares_found'] or host_result['files_downloaded']:
                self.results['hosts_analyzed'].append(host_result)
                self.results['statistics']['hosts_with_shares'] += 1
                self._save_results()
        
        # Resumen final
        self._print_summary()
    
    def _check_smb_shares(self, ip: str, host_result: Dict, max_size: int, max_files: int):
        """Verifica recursos compartidos SMB/SAMBA"""
        if not SMB_AVAILABLE:
            print(f"    [!] Librería pysmb no disponible. Instala: pip install pysmb")
            return
        
        host_result['services_checked'].append('SMB')
        
        try:
            # Intentar conexión anónima
            conn = SMBConnection('', '', 'scanner', ip, use_ntlm_v2=True, is_direct_tcp=True)
            
            if conn.connect(ip, 445, timeout=5):
                print(f"    [✓] Conexión SMB anónima exitosa")
                
                # Listar recursos compartidos
                shares = conn.listShares(timeout=10)
                
                for share in shares:
                    if share.name not in ['IPC$', 'ADMIN$', 'C$', 'print$']:
                        share_name = share.name
                        print(f"        [+] Recurso compartido encontrado: {share_name}")
                        
                        share_info = {
                            "type": "SMB",
                            "name": share_name,
                            "path": f"\\\\{ip}\\{share_name}",
                            "accessible": True,
                            "files": []
                        }
                        
                        try:
                            # Listar archivos en el recurso compartido
                            files = conn.listPath(share_name, '/')
                            file_count = 0
                            
                            for file in files:
                                if not file.isDirectory and file.filename not in ['.', '..']:
                                    if file_count >= max_files:
                                        print(f"        [!] Límite de {max_files} archivos alcanzado")
                                        break
                                    
                                    if file.file_size <= max_size:
                                        # Descargar archivo
                                        self._download_smb_file(conn, ip, share_name, file, host_result, share_info)
                                        file_count += 1
                                    else:
                                        print(f"        [-] Archivo muy grande: {file.filename} ({file.file_size} bytes)")
                            
                            self.results['statistics']['smb_shares_found'] += 1
                            
                        except Exception as e:
                            print(f"        [!] Error listando archivos: {str(e)}")
                            share_info['accessible'] = False
                        
                        host_result['shares_found'].append(share_info)
                
                conn.close()
                
        except Exception as e:
            print(f"    [!] Error en SMB: {str(e)}")
    
    def _download_smb_file(self, conn, ip: str, share: str, file_obj, host_result: Dict, share_info: Dict):
        """Descarga un archivo desde SMB"""
        try:
            # Crear directorio para el host
            host_dir = Path(self.output_dir) / ip / 'SMB' / share
            host_dir.mkdir(parents=True, exist_ok=True)
            
            # Ruta de archivo local
            local_path = host_dir / file_obj.filename
            
            # Descargar archivo
            with open(local_path, 'wb') as f:
                conn.retrieveFile(share, f"/{file_obj.filename}", f)
            
            file_info = {
                "filename": file_obj.filename,
                "size": file_obj.file_size,
                "share": share,
                "local_path": str(local_path),
                "downloaded_at": datetime.now().isoformat()
            }
            
            print(f"        [✓] Descargado: {file_obj.filename} ({file_obj.file_size} bytes)")
            
            host_result['files_downloaded'].append(file_info)
            share_info['files'].append(file_info)
            self.results['files_downloaded'].append(file_info)
            self.results['statistics']['total_files_downloaded'] += 1
            self.results['statistics']['total_size_bytes'] += file_obj.file_size
            self._save_results()
            
        except Exception as e:
            print(f"        [!] Error descargando {file_obj.filename}: {str(e)}")
            self.results['statistics']['failed_downloads'] += 1
    
    def _check_ftp_access(self, ip: str, host_result: Dict, max_size: int, max_files: int):
        """Verifica acceso FTP anónimo"""
        host_result['services_checked'].append('FTP')
        
        try:
            # Intentar conexión FTP anónima
            ftp = ftplib.FTP(timeout=10)
            ftp.connect(ip, 21)
            ftp.login()  # Login anónimo
            
            print(f"    [✓] Acceso FTP anónimo exitoso")
            self.results['statistics']['ftp_accessible'] += 1
            
            share_info = {
                "type": "FTP",
                "name": "FTP Anonymous",
                "path": f"ftp://{ip}/",
                "accessible": True,
                "files": []
            }
            
            # Listar archivos
            file_list = []
            try:
                ftp.retrlines('LIST', file_list.append)
            except:
                ftp.retrlines('NLST', file_list.append)
            
            file_count = 0
            for entry in file_list:
                if file_count >= max_files:
                    print(f"        [!] Límite de {max_files} archivos alcanzado")
                    break
                
                # Parsear entrada (formato puede variar)
                parts = entry.split()
                if len(parts) > 0:
                    filename = parts[-1]
                    
                    # Intentar obtener tamaño
                    try:
                        size = ftp.size(filename)
                        if size and size <= max_size:
                            self._download_ftp_file(ftp, ip, filename, size, host_result, share_info)
                            file_count += 1
                        elif size and size > max_size:
                            print(f"        [-] Archivo muy grande: {filename} ({size} bytes)")
                    except:
                        # Si no se puede obtener tamaño, intentar descargar
                        try:
                            self._download_ftp_file(ftp, ip, filename, 0, host_result, share_info)
                            file_count += 1
                        except:
                            pass
            
            host_result['shares_found'].append(share_info)
            ftp.quit()
            
        except ftplib.error_perm as e:
            print(f"    [!] FTP requiere autenticación: {str(e)}")
        except Exception as e:
            print(f"    [!] Error en FTP: {str(e)}")
    
    def _download_ftp_file(self, ftp, ip: str, filename: str, size: int, host_result: Dict, share_info: Dict):
        """Descarga un archivo desde FTP"""
        try:
            # Crear directorio para el host
            host_dir = Path(self.output_dir) / ip / 'FTP'
            host_dir.mkdir(parents=True, exist_ok=True)
            
            # Ruta de archivo local
            local_path = host_dir / filename
            
            # Descargar archivo
            with open(local_path, 'wb') as f:
                ftp.retrbinary(f'RETR {filename}', f.write)
            
            # Obtener tamaño real del archivo descargado
            actual_size = local_path.stat().st_size
            
            file_info = {
                "filename": filename,
                "size": actual_size,
                "service": "FTP",
                "local_path": str(local_path),
                "downloaded_at": datetime.now().isoformat()
            }
            
            print(f"        [✓] Descargado: {filename} ({actual_size} bytes)")
            
            host_result['files_downloaded'].append(file_info)
            share_info['files'].append(file_info)
            self.results['files_downloaded'].append(file_info)
            self.results['statistics']['total_files_downloaded'] += 1
            self.results['statistics']['total_size_bytes'] += actual_size
            self._save_results()
            
        except Exception as e:
            print(f"        [!] Error descargando {filename}: {str(e)}")
            self.results['statistics']['failed_downloads'] += 1
    
    def _check_http_directories(self, ip: str, host_result: Dict, ports: List, max_size: int, max_files: int):
        """Verifica directorios HTTP accesibles"""
        if not REQUESTS_AVAILABLE:
            print(f"    [!] Librería requests no disponible")
            return
        
        host_result['services_checked'].append('HTTP')
        
        # Detectar si es HTTP o HTTPS
        http_ports = []
        for port in ports:
            if port.get('port') in [80, 443, 8080]:
                protocol = 'https' if port.get('port') == 443 else 'http'
                http_ports.append((protocol, port.get('port')))
        
        # Directorios comunes a verificar
        common_dirs = [
            '/shared/', '/files/', '/public/', '/downloads/', '/docs/', 
            '/uploads/', '/backup/', '/data/', '/share/'
        ]
        
        for protocol, port in http_ports:
            base_url = f"{protocol}://{ip}:{port}"
            
            for directory in common_dirs:
                try:
                    url = base_url + directory
                    response = requests.get(url, timeout=5, verify=False, allow_redirects=True)
                    
                    if response.status_code == 200:
                        # Verificar si es un listado de directorio
                        if 'Index of' in response.text or '<a href=' in response.text:
                            print(f"        [+] Directorio accesible: {url}")
                            
                            share_info = {
                                "type": "HTTP",
                                "name": directory,
                                "path": url,
                                "accessible": True,
                                "files": []
                            }
                            
                            # Intentar parsear archivos (básico)
                            # Esto es simplificado, en producción usar BeautifulSoup
                            self.results['statistics']['http_directories_found'] += 1
                            host_result['shares_found'].append(share_info)
                            
                except requests.exceptions.RequestException:
                    pass
                except Exception as e:
                    pass
    
    def _print_summary(self):
        """Muestra resumen de la recolección"""
        print("\n" + "="*70)
        print("  RESUMEN DE RECOLECCIÓN DE ARCHIVOS")
        print("="*70)
        
        stats = self.results['statistics']
        
        print(f"\nHosts analizados:           {stats['total_hosts']}")
        print(f"Hosts con recursos:         {stats['hosts_with_shares']}")
        print(f"Recursos SMB encontrados:   {stats['smb_shares_found']}")
        print(f"Servidores FTP accesibles:  {stats['ftp_accessible']}")
        print(f"Directorios HTTP:           {stats['http_directories_found']}")
        print(f"\nArchivos descargados:       {stats['total_files_downloaded']}")
        print(f"Tamaño total:               {self._format_size(stats['total_size_bytes'])}")
        print(f"Descargas fallidas:         {stats['failed_downloads']}")
        print(f"\nDirectorio de salida:       {self.output_dir}")
        print(f"Archivo de resultados:      {self.output_json}")
        print("="*70)
    
    def _format_size(self, bytes: int) -> str:
        """Formatea tamaño de bytes a formato legible"""
        for unit in ['B', 'KB', 'MB', 'GB']:
            if bytes < 1024.0:
                return f"{bytes:.2f} {unit}"
            bytes /= 1024.0
        return f"{bytes:.2f} TB"

