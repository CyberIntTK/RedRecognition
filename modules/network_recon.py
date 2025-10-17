#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Módulo de Reconocimiento de Red WiFi
Realiza escaneo completo de la red: hosts, puertos, servicios, IP pública, etc.
Optimizado para Kali Linux con auto-detección de red WiFi
"""

import json
import os
import socket
import platform
import subprocess
import threading
import re
from datetime import datetime
from typing import Dict, List, Optional
import ipaddress
import requests
import netifaces
from scapy.all import ARP, Ether, srp, conf
import nmap

class NetworkRecon:
    """Clase para realizar reconocimiento completo de red"""
    
    def __init__(self, output_file: str = "reconocimiento.json", 
                 interface: Optional[str] = None,
                 network_range: Optional[str] = None):
        """
        Inicializa el módulo de reconocimiento
        
        Args:
            output_file: Ruta del archivo JSON de salida
            interface: Interfaz de red a utilizar
            network_range: Rango de red personalizado
        """
        self.output_file = output_file
        self.interface = interface
        self.network_range = network_range
        self.lock = threading.Lock()
        self.wifi_info = None  # Información de la conexión WiFi
        
        # Cargar escaneos previos si existen
        self.previous_scan = self._load_previous_scan()
        
        # Estructura de datos para almacenar resultados
        self.results = {
            "timestamp": datetime.now().isoformat(),
            "scan_info": {},
            "network_info": {},
            "wifi_connection": {},
            "public_ip": {},
            "local_info": {},
            "discovered_hosts": [],
            "scan_summary": {}
        }
        
        # Guardar estructura inicial
        self._save_results()
    
    def _load_previous_scan(self) -> Dict:
        """Carga un escaneo previo si existe"""
        try:
            if os.path.exists(self.output_file):
                with open(self.output_file, 'r', encoding='utf-8') as f:
                    data = json.load(f)
                    if data.get('discovered_hosts'):
                        print(f"[*] Escaneo previo encontrado con {len(data['discovered_hosts'])} hosts")
                        return data
        except Exception as e:
            pass
        return {}
    
    def _save_results(self):
        """Guarda los resultados en el archivo JSON de forma segura"""
        with self.lock:
            try:
                with open(self.output_file, 'w', encoding='utf-8') as f:
                    json.dump(self.results, f, indent=4, ensure_ascii=False)
            except Exception as e:
                print(f"[!] Error guardando resultados: {str(e)}")
    
    def _update_scan_info(self, key: str, value):
        """Actualiza información del escaneo y guarda"""
        self.results["scan_info"][key] = value
        self._save_results()
    
    def detect_wifi_connection(self) -> Dict:
        """
        Detecta automáticamente la conexión WiFi activa en Kali Linux
        
        Returns:
            Diccionario con información de la conexión WiFi
        """
        wifi_data = {
            "connected": False,
            "interface": "N/A",
            "ssid": "N/A",
            "bssid": "N/A",
            "frequency": "N/A",
            "channel": "N/A",
            "signal_quality": "N/A",
            "signal_level": "N/A",
            "ip_address": "N/A",
            "netmask": "N/A",
            "gateway": "N/A",
            "network_range": "N/A"
        }
        
        try:
            # Método 1: Intentar con nmcli (Network Manager)
            wifi_iface = self._detect_wifi_interface_nmcli()
            if wifi_iface:
                wifi_data["interface"] = wifi_iface
                wifi_data["connected"] = True
                
                # Obtener SSID, BSSID, etc.
                wifi_details = self._get_wifi_details_nmcli(wifi_iface)
                wifi_data.update(wifi_details)
            
            # Método 2: Intentar con iwconfig si nmcli no funcionó
            if not wifi_data["connected"]:
                wifi_iface = self._detect_wifi_interface_iwconfig()
                if wifi_iface:
                    wifi_data["interface"] = wifi_iface
                    wifi_data["connected"] = True
                    
                    # Obtener detalles con iwconfig
                    wifi_details = self._get_wifi_details_iwconfig(wifi_iface)
                    wifi_data.update(wifi_details)
            
            # Método 3: Buscar interfaces WiFi manualmente si nada funcionó
            if not wifi_data["connected"]:
                wifi_iface = self._detect_wifi_interface_manual()
                if wifi_iface:
                    wifi_data["interface"] = wifi_iface
                    wifi_data["connected"] = True
                    wifi_data["ssid"] = "Conectado (no se pudo obtener SSID)"
            
            # Si se detectó una interfaz, obtener info de red
            if wifi_data["connected"]:
                # Si el usuario especificó una interfaz, usarla en lugar de la auto-detectada
                if self.interface:
                    wifi_data["interface"] = self.interface
                
                # Obtener información de IP, gateway, etc.
                network_info = self._get_network_info(wifi_data["interface"])
                wifi_data.update(network_info)
                
                # Actualizar la interfaz y rango de red para usar en el escaneo
                self.interface = wifi_data["interface"]
                if not self.network_range and wifi_data["network_range"] != "N/A":
                    self.network_range = wifi_data["network_range"]
        
        except Exception as e:
            print(f"[!] Error detectando WiFi: {str(e)}")
        
        # Guardar información de WiFi
        self.wifi_info = wifi_data
        self.results["wifi_connection"] = wifi_data
        self._save_results()
        
        return wifi_data
    
    def _detect_wifi_interface_nmcli(self) -> Optional[str]:
        """Detecta interfaz WiFi usando nmcli (Network Manager)"""
        try:
            result = subprocess.run(
                ['nmcli', '-t', '-f', 'DEVICE,TYPE,STATE', 'device'],
                capture_output=True,
                text=True,
                timeout=5
            )
            
            if result.returncode == 0:
                for line in result.stdout.strip().split('\n'):
                    parts = line.split(':')
                    if len(parts) >= 3:
                        device, dev_type, state = parts[0], parts[1], parts[2]
                        if dev_type == 'wifi' and state == 'connected':
                            return device
        except Exception:
            pass
        return None
    
    def _detect_wifi_interface_iwconfig(self) -> Optional[str]:
        """Detecta interfaz WiFi usando iwconfig"""
        try:
            result = subprocess.run(
                ['iwconfig'],
                capture_output=True,
                text=True,
                timeout=5
            )
            
            if result.returncode == 0:
                # Buscar líneas que contengan ESSID
                for line in result.stdout.split('\n'):
                    if 'ESSID:' in line and 'ESSID:off' not in line:
                        # Extraer nombre de interfaz (primera palabra)
                        interface = line.split()[0]
                        return interface
        except Exception:
            pass
        return None
    
    def _detect_wifi_interface_manual(self) -> Optional[str]:
        """Detecta interfaz WiFi manualmente buscando wlan*, wlp*, etc."""
        try:
            interfaces = netifaces.interfaces()
            for iface in interfaces:
                # Buscar interfaces que típicamente son WiFi
                if any(iface.startswith(prefix) for prefix in ['wlan', 'wlp', 'wlo', 'wl']):
                    # Verificar que tenga IP asignada
                    if netifaces.AF_INET in netifaces.ifaddresses(iface):
                        return iface
        except Exception:
            pass
        return None
    
    def _get_wifi_details_nmcli(self, interface: str) -> Dict:
        """Obtiene detalles de la conexión WiFi usando nmcli"""
        details = {}
        
        try:
            # Obtener detalles de la conexión activa
            result = subprocess.run(
                ['nmcli', '-t', '-f', 'GENERAL.CONNECTION,GENERAL.DEVICE', 'device', 'show', interface],
                capture_output=True,
                text=True,
                timeout=5
            )
            
            # Obtener información de la red WiFi
            result2 = subprocess.run(
                ['nmcli', '-t', '-f', 'SSID,BSSID,FREQ,CHAN,SIGNAL', 'device', 'wifi', 'list', 'ifname', interface],
                capture_output=True,
                text=True,
                timeout=5
            )
            
            if result2.returncode == 0:
                lines = result2.stdout.strip().split('\n')
                if lines:
                    # Primera línea es la red conectada (marcada con *)
                    for line in lines:
                        if line.startswith('*'):
                            parts = line.replace('*', '').split(':')
                            if len(parts) >= 5:
                                details["ssid"] = parts[0].strip()
                                details["bssid"] = parts[1].strip()
                                details["frequency"] = parts[2].strip() + " MHz"
                                details["channel"] = parts[3].strip()
                                signal = parts[4].strip()
                                details["signal_level"] = signal + " dBm"
                                details["signal_quality"] = self._calculate_signal_quality(signal)
                            break
        except Exception as e:
            pass
        
        return details
    
    def _get_wifi_details_iwconfig(self, interface: str) -> Dict:
        """Obtiene detalles de la conexión WiFi usando iwconfig"""
        details = {}
        
        try:
            result = subprocess.run(
                ['iwconfig', interface],
                capture_output=True,
                text=True,
                timeout=5
            )
            
            if result.returncode == 0:
                output = result.stdout
                
                # Extraer SSID
                ssid_match = re.search(r'ESSID:"([^"]+)"', output)
                if ssid_match:
                    details["ssid"] = ssid_match.group(1)
                
                # Extraer BSSID (Access Point)
                bssid_match = re.search(r'Access Point: ([0-9A-Fa-f:]+)', output)
                if bssid_match:
                    details["bssid"] = bssid_match.group(1)
                
                # Extraer frecuencia
                freq_match = re.search(r'Frequency:([\d.]+) GHz', output)
                if freq_match:
                    freq_ghz = float(freq_match.group(1))
                    details["frequency"] = f"{freq_ghz} GHz"
                    # Estimar canal
                    if freq_ghz < 3:
                        channel = int((freq_ghz - 2.407) / 0.005)
                    else:
                        channel = int((freq_ghz - 5.000) / 0.005)
                    details["channel"] = str(channel)
                
                # Extraer calidad de señal
                quality_match = re.search(r'Link Quality=(\d+)/(\d+)', output)
                if quality_match:
                    quality = int(quality_match.group(1))
                    max_quality = int(quality_match.group(2))
                    percentage = int((quality / max_quality) * 100)
                    details["signal_quality"] = f"{quality}/{max_quality} ({percentage}%)"
                
                # Extraer nivel de señal
                signal_match = re.search(r'Signal level=(-?\d+) dBm', output)
                if signal_match:
                    details["signal_level"] = signal_match.group(1) + " dBm"
        
        except Exception:
            pass
        
        return details
    
    def _calculate_signal_quality(self, signal_dbm: str) -> str:
        """Calcula la calidad de señal en porcentaje a partir de dBm"""
        try:
            dbm = int(signal_dbm)
            # Fórmula aproximada: -30 dBm = 100%, -90 dBm = 0%
            if dbm >= -30:
                percentage = 100
            elif dbm <= -90:
                percentage = 0
            else:
                percentage = int(((dbm + 90) / 60) * 100)
            return f"{percentage}%"
        except:
            return "N/A"
    
    def _get_network_info(self, interface: str) -> Dict:
        """Obtiene información de red (IP, gateway, máscara, rango)"""
        network_info = {
            "ip_address": "N/A",
            "netmask": "N/A",
            "gateway": "N/A",
            "network_range": "N/A"
        }
        
        try:
            # Obtener IP y máscara de red
            if netifaces.AF_INET in netifaces.ifaddresses(interface):
                ipv4_info = netifaces.ifaddresses(interface)[netifaces.AF_INET][0]
                ip_addr = ipv4_info.get('addr')
                netmask = ipv4_info.get('netmask')
                
                if ip_addr:
                    network_info["ip_address"] = ip_addr
                if netmask:
                    network_info["netmask"] = netmask
                
                # Calcular rango de red
                if ip_addr and netmask:
                    network = ipaddress.IPv4Network(f"{ip_addr}/{netmask}", strict=False)
                    network_info["network_range"] = str(network)
            
            # Obtener gateway
            gws = netifaces.gateways()
            if 'default' in gws and netifaces.AF_INET in gws['default']:
                gateway_info = gws['default'][netifaces.AF_INET]
                if gateway_info[1] == interface:
                    network_info["gateway"] = gateway_info[0]
        
        except Exception:
            pass
        
        return network_info
    
    def get_local_ip_info(self) -> Dict:
        """Obtiene información de la IP local y configuración de red"""
        print("[*] Recopilando información de red local...")
        
        local_info = {
            "hostname": socket.gethostname(),
            "platform": platform.system(),
            "platform_release": platform.release(),
            "platform_version": platform.version(),
            "architecture": platform.machine(),
            "processor": platform.processor(),
            "interfaces": []
        }
        
        # Obtener información de todas las interfaces
        try:
            for iface_name in netifaces.interfaces():
                iface_info = {
                    "name": iface_name,
                    "addresses": {}
                }
                
                # IPv4
                if netifaces.AF_INET in netifaces.ifaddresses(iface_name):
                    ipv4_info = netifaces.ifaddresses(iface_name)[netifaces.AF_INET][0]
                    iface_info["addresses"]["ipv4"] = {
                        "addr": ipv4_info.get('addr'),
                        "netmask": ipv4_info.get('netmask'),
                        "broadcast": ipv4_info.get('broadcast')
                    }
                
                # MAC
                if netifaces.AF_LINK in netifaces.ifaddresses(iface_name):
                    mac_info = netifaces.ifaddresses(iface_name)[netifaces.AF_LINK][0]
                    iface_info["addresses"]["mac"] = mac_info.get('addr')
                
                local_info["interfaces"].append(iface_info)
        
        except Exception as e:
            print(f"[!] Error obteniendo interfaces: {str(e)}")
        
        # Guardar gateway predeterminado
        try:
            gws = netifaces.gateways()
            if 'default' in gws and netifaces.AF_INET in gws['default']:
                local_info["default_gateway"] = {
                    "gateway": gws['default'][netifaces.AF_INET][0],
                    "interface": gws['default'][netifaces.AF_INET][1]
                }
        except Exception as e:
            print(f"[!] Error obteniendo gateway: {str(e)}")
        
        self.results["local_info"] = local_info
        self._save_results()
        
        print(f"    [✓] Hostname: {local_info['hostname']}")
        print(f"    [✓] Interfaces encontradas: {len(local_info['interfaces'])}")
        
        return local_info
    
    def get_public_ip(self) -> Dict:
        """Obtiene la IP pública y su información geográfica"""
        print("[*] Obteniendo IP pública...")
        
        public_info = {
            "ip": None,
            "location": {},
            "error": None
        }
        
        try:
            # Obtener IP pública
            response = requests.get('https://api.ipify.org?format=json', timeout=10)
            public_info["ip"] = response.json()['ip']
            print(f"    [✓] IP Pública: {public_info['ip']}")
            
            # Obtener información geográfica
            try:
                geo_response = requests.get(
                    f'http://ip-api.com/json/{public_info["ip"]}',
                    timeout=10
                )
                geo_data = geo_response.json()
                
                if geo_data.get('status') == 'success':
                    public_info["location"] = {
                        "country": geo_data.get('country'),
                        "region": geo_data.get('regionName'),
                        "city": geo_data.get('city'),
                        "zip": geo_data.get('zip'),
                        "lat": geo_data.get('lat'),
                        "lon": geo_data.get('lon'),
                        "timezone": geo_data.get('timezone'),
                        "isp": geo_data.get('isp'),
                        "org": geo_data.get('org'),
                        "as": geo_data.get('as')
                    }
                    print(f"    [✓] ISP: {geo_data.get('isp')}")
                    print(f"    [✓] Ubicación: {geo_data.get('city')}, {geo_data.get('country')}")
            
            except Exception as e:
                print(f"    [!] No se pudo obtener información geográfica: {str(e)}")
        
        except Exception as e:
            public_info["error"] = str(e)
            print(f"    [!] Error obteniendo IP pública: {str(e)}")
        
        self.results["public_ip"] = public_info
        self._save_results()
        
        return public_info
    
    def get_network_range(self) -> str:
        """Determina el rango de red a escanear"""
        if self.network_range:
            return self.network_range
        
        # Auto-detectar el rango de red
        try:
            if self.interface:
                iface = self.interface
            else:
                # Obtener la interfaz predeterminada
                gws = netifaces.gateways()
                if 'default' in gws and netifaces.AF_INET in gws['default']:
                    iface = gws['default'][netifaces.AF_INET][1]
                else:
                    return "192.168.1.0/24"  # Fallback
            
            # Obtener IP y máscara de la interfaz
            if netifaces.AF_INET in netifaces.ifaddresses(iface):
                ipv4_info = netifaces.ifaddresses(iface)[netifaces.AF_INET][0]
                ip = ipv4_info.get('addr')
                netmask = ipv4_info.get('netmask')
                
                if ip and netmask:
                    network = ipaddress.IPv4Network(f"{ip}/{netmask}", strict=False)
                    return str(network)
        
        except Exception as e:
            print(f"[!] Error determinando rango de red: {str(e)}")
        
        return "192.168.1.0/24"  # Fallback
    
    def scan_network_hosts(self, network_range: str) -> List[Dict]:
        """
        Escanea la red para descubrir hosts activos usando ARP
        
        Args:
            network_range: Rango de red en formato CIDR
            
        Returns:
            Lista de hosts descubiertos
        """
        print(f"[*] Escaneando red: {network_range}")
        print("    [*] Esto puede tomar varios minutos...")
        
        discovered_hosts = []
        
        try:
            # Configurar scapy para ser menos verboso
            conf.verb = 0
            
            # Crear paquete ARP
            arp = ARP(pdst=network_range)
            ether = Ether(dst="ff:ff:ff:ff:ff:ff")
            packet = ether/arp
            
            # Enviar y recibir paquetes
            result = srp(packet, timeout=3, verbose=0)[0]
            
            print(f"    [✓] Hosts activos encontrados: {len(result)}")
            
            for sent, received in result:
                host_info = {
                    "ip": received.psrc,
                    "mac": received.hwsrc,
                    "vendor": self._get_mac_vendor(received.hwsrc),
                    "hostname": self._get_hostname(received.psrc),
                    "ports": [],
                    "services": {},
                    "os_detection": {}
                }
                
                discovered_hosts.append(host_info)
                
                # Actualizar y guardar inmediatamente
                self.results["discovered_hosts"] = discovered_hosts
                self._save_results()
                
                print(f"    [✓] Host encontrado: {host_info['ip']} ({host_info['mac']}) - {host_info['hostname']}")
        
        except Exception as e:
            print(f"    [!] Error en escaneo de red: {str(e)}")
        
        return discovered_hosts
    
    def _get_hostname(self, ip: str) -> str:
        """Intenta obtener el hostname de una IP"""
        try:
            return socket.gethostbyaddr(ip)[0]
        except:
            return "Unknown"
    
    def _get_mac_vendor(self, mac: str) -> str:
        """Intenta identificar el fabricante del dispositivo por MAC"""
        try:
            # Usar API de macvendors.com
            response = requests.get(f'https://api.macvendors.com/{mac}', timeout=2)
            if response.status_code == 200:
                return response.text
        except:
            pass
        return "Unknown"
    
    def scan_host_ports(self, host_ip: str, quick: bool = False) -> Dict:
        """
        Escanea puertos y servicios de un host específico
        
        Args:
            host_ip: IP del host a escanear
            quick: Si True, escanea solo puertos comunes
            
        Returns:
            Información de puertos y servicios
        """
        print(f"    [*] Escaneando puertos en {host_ip}...")
        
        port_info = {
            "open_ports": [],
            "services": {},
            "os_detection": {}
        }
        
        try:
            nm = nmap.PortScanner()
            
            # Determinar argumentos de escaneo
            if quick:
                # Escaneo rápido: top 100 puertos
                arguments = '-F -T4'
            else:
                # Escaneo completo: top 1000 puertos con detección de servicios
                arguments = '-sV -T4 --top-ports 1000'
            
            # Realizar escaneo
            nm.scan(host_ip, arguments=arguments)
            
            if host_ip in nm.all_hosts():
                for proto in nm[host_ip].all_protocols():
                    ports = nm[host_ip][proto].keys()
                    
                    for port in ports:
                        port_state = nm[host_ip][proto][port]['state']
                        
                        if port_state == 'open':
                            port_detail = {
                                "port": port,
                                "protocol": proto,
                                "state": port_state,
                                "service": nm[host_ip][proto][port].get('name', 'unknown'),
                                "product": nm[host_ip][proto][port].get('product', ''),
                                "version": nm[host_ip][proto][port].get('version', ''),
                                "extrainfo": nm[host_ip][proto][port].get('extrainfo', '')
                            }
                            
                            port_info["open_ports"].append(port_detail)
                            port_info["services"][f"{port}/{proto}"] = {
                                "service": port_detail["service"],
                                "product": port_detail["product"],
                                "version": port_detail["version"]
                            }
                
                # Detección de OS si está disponible
                if 'osmatch' in nm[host_ip]:
                    os_matches = nm[host_ip]['osmatch']
                    if os_matches:
                        port_info["os_detection"] = {
                            "name": os_matches[0].get('name', 'Unknown'),
                            "accuracy": os_matches[0].get('accuracy', '0'),
                            "type": os_matches[0].get('osclass', [{}])[0].get('type', 'Unknown') if os_matches[0].get('osclass') else 'Unknown'
                        }
                
                print(f"        [✓] Puertos abiertos: {len(port_info['open_ports'])}")
        
        except Exception as e:
            print(f"        [!] Error escaneando puertos: {str(e)}")
        
        return port_info
    
    def run_full_reconnaissance(self, quick_scan: bool = False, skip_port_scan: bool = False):
        """
        Ejecuta el reconocimiento completo de la red
        
        Args:
            quick_scan: Si True, realiza escaneos más rápidos pero menos completos
            skip_port_scan: Si True, omite el escaneo de puertos (solo descubre hosts)
        """
        # Timestamp de inicio
        start_time = datetime.now()
        self._update_scan_info("start_time", start_time.isoformat())
        
        if skip_port_scan:
            self._update_scan_info("scan_type", "discovery_only")
        elif quick_scan:
            self._update_scan_info("scan_type", "quick")
        else:
            self._update_scan_info("scan_type", "full")
        
        # 1. Información local
        local_info = self.get_local_ip_info()
        
        # 2. IP Pública
        public_ip = self.get_public_ip()
        
        # 3. Determinar rango de red
        network_range = self.get_network_range()
        self.results["network_info"]["range"] = network_range
        self._save_results()
        print(f"[*] Rango de red detectado: {network_range}")
        
        # 4. Escanear hosts en la red
        discovered_hosts = self.scan_network_hosts(network_range)
        
        # 5. Escanear puertos y servicios de cada host
        if not skip_port_scan and discovered_hosts:
            print(f"\n[*] Iniciando escaneo de puertos en {len(discovered_hosts)} hosts...")
            
            # Crear un diccionario de hosts previos para búsqueda rápida
            previous_hosts = {}
            if self.previous_scan and self.previous_scan.get('discovered_hosts'):
                for prev_host in self.previous_scan['discovered_hosts']:
                    previous_hosts[prev_host['ip']] = prev_host
            
            hosts_to_scan = 0
            hosts_skipped = 0
            
            for idx, host in enumerate(discovered_hosts):
                host_ip = host['ip']
                
                # Verificar si este host ya fue escaneado previamente
                if host_ip in previous_hosts:
                    prev_host = previous_hosts[host_ip]
                    
                    # Si el host previo tiene puertos escaneados, reutilizar
                    if prev_host.get('ports') and len(prev_host['ports']) > 0:
                        print(f"\n[*] Host {idx+1}/{len(discovered_hosts)}: {host_ip}")
                        print(f"    [✓] Ya escaneado previamente con {len(prev_host['ports'])} puertos - REUTILIZANDO datos")
                        
                        # Reutilizar información previa
                        host['ports'] = prev_host['ports']
                        host['services'] = prev_host.get('services', {})
                        host['os_detection'] = prev_host.get('os_detection', {})
                        
                        hosts_skipped += 1
                        
                        # Guardar
                        self.results["discovered_hosts"] = discovered_hosts
                        self._save_results()
                        continue
                
                # Si no está en caché o no tiene puertos, escanear
                print(f"\n[*] Escaneando host {idx+1}/{len(discovered_hosts)}: {host_ip}")
                hosts_to_scan += 1
                
                port_info = self.scan_host_ports(host_ip, quick=quick_scan)
                
                # Actualizar información del host
                host['ports'] = port_info['open_ports']
                host['services'] = port_info['services']
                host['os_detection'] = port_info['os_detection']
                
                # Guardar después de cada host
                self.results["discovered_hosts"] = discovered_hosts
                self._save_results()
            
            if hosts_skipped > 0:
                print(f"\n[✓] Optimización: {hosts_skipped} hosts saltados (ya escaneados previamente)")
                print(f"[✓] Hosts escaneados: {hosts_to_scan}")
                print(f"[✓] Tiempo ahorrado: ~{hosts_skipped * 30} segundos")
        
        # 6. Generar resumen
        end_time = datetime.now()
        duration = (end_time - start_time).total_seconds()
        
        total_open_ports = sum(len(host.get('ports', [])) for host in discovered_hosts)
        
        summary = {
            "scan_duration_seconds": duration,
            "total_hosts_discovered": len(discovered_hosts),
            "total_open_ports": total_open_ports,
            "network_range_scanned": network_range,
            "end_time": end_time.isoformat()
        }
        
        self.results["scan_summary"] = summary
        self._save_results()
        
        # Mostrar resumen
        print("\n" + "="*60)
        print("RESUMEN DEL RECONOCIMIENTO")
        print("="*60)
        print(f"Duración del escaneo: {duration:.2f} segundos")
        print(f"Hosts descubiertos: {summary['total_hosts_discovered']}")
        print(f"Total de puertos abiertos: {summary['total_open_ports']}")
        print(f"Rango escaneado: {network_range}")
        print("="*60)

