#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
RED RECOGNITION - PENTESTING AUTOMATION SUITE
Sistema Modular de Reconocimiento y Explotación de Redes
Versión: 2.0 - Full Offensive Suite
"""

import os
import sys
import json
import argparse
from datetime import datetime

# Importar módulos
from modules.network_recon import NetworkRecon
from modules.file_harvester import FileHarvester
from modules.router_exploit import RouterExploit
from modules.camera_exploit import CameraExploit
from modules.service_exploit import ServiceExploit
from modules.credential_harvest import CredentialHarvester
from modules.backdoor_manager import BackdoorManager
from modules.report_generator import ReportGenerator

def print_banner():
    """Muestra el banner de la aplicación"""
    banner = """
    ╔═══════════════════════════════════════════════════════════╗
    ║         RED RECOGNITION - PENTESTING AUTOMATION           ║
    ║          Sistema Modular de Ataque y Análisis             ║
    ║                      Versión 2.0                          ║
    ╚═══════════════════════════════════════════════════════════╝
    """
    print(banner)

def check_root():
    """Verifica si el script se está ejecutando como root"""
    if sys.platform == 'linux' and os.geteuid() != 0:
        print("╔════════════════════════════════════════════════════════════╗")
        print("║                    ⚠️  ADVERTENCIA  ⚠️                      ║")
        print("║                                                            ║")
        print("║  Este script requiere privilegios de root para funcionar  ║")
        print("║  correctamente y ejecutar ataques reales.                 ║")
        print("║                                                            ║")
        print("║  Por favor, ejecuta el script con sudo:                   ║")
        print("║      sudo python3 main.py                                 ║")
        print("╚════════════════════════════════════════════════════════════╝")
        print()
        respuesta = input("¿Deseas continuar de todas formas? (s/N): ")
        if respuesta.lower() != 's':
            print("\n[!] Saliendo...")
            sys.exit(1)
        print("\n[!] Continuando sin privilegios de root. Funcionalidad limitada.\n")

def show_legal_warning():
    """Muestra advertencia legal"""
    print("\n" + "="*70)
    print("  ⚠️  ADVERTENCIA LEGAL  ⚠️")
    print("="*70)
    print("""
Este software está diseñado EXCLUSIVAMENTE para:
  • Pruebas de penetración autorizadas
  • Auditorías de seguridad con permiso explícito
  • Evaluaciones de seguridad en redes propias

USO ILEGAL DE ESTA HERRAMIENTA ES UN DELITO.

El uso no autorizado de esta herramienta contra sistemas que no te
pertenecen o sin permiso explícito es ILEGAL y puede resultar en:
  • Procesamiento criminal
  • Multas significativas
  • Tiempo en prisión

Al continuar, aceptas que:
  1. Tienes autorización explícita para auditar esta red
  2. Eres responsable de cualquier acción realizada
  3. Entiendes las implicaciones legales

""")
    print("="*70)
    
    respuesta = input("\n¿Tienes AUTORIZACIÓN EXPLÍCITA para auditar esta red? (SI/no): ")
    if respuesta.upper() != 'SI':
        print("\n[!] Saliendo por seguridad legal...")
        sys.exit(1)
    
    print("\n[✓] Confirmación recibida. Continuando...\n")

def interactive_menu():
    """Menú interactivo para selección de módulos"""
    print("\n" + "="*70)
    print("  SELECCIÓN DE MODO DE EJECUCIÓN")
    print("="*70)
    print("""
[1] 🎯 Ejecutar TODO (Full Pentesting Suite)
[2] 📋 Seleccionar módulos manualmente
[3] ⚡ Modo rápido (solo credenciales y servicios críticos)
[4] 🔍 Solo reconocimiento (sin ataques)
[5] 📊 Solo generar informe consolidado
[0] ❌ Salir
""")
    
    while True:
        try:
            choice = input("Selecciona una opción [0-5]: ").strip()
            
            if choice in ['0', '1', '2', '3', '4', '5']:
                return int(choice)
            else:
                print("[!] Opción inválida. Intenta de nuevo.")
        except KeyboardInterrupt:
            print("\n[!] Saliendo...")
            sys.exit(0)

def ask_module_execution(module_name: str, description: str, default: bool = True) -> bool:
    """Pregunta si ejecutar un módulo específico"""
    default_str = "S/n" if default else "s/N"
    prompt = f"\n[?] {module_name}: {description}\n    ¿Ejecutar? ({default_str}): "
    
    response = input(prompt).strip().lower()
    
    if default:
        return response != 'n'
    else:
        return response == 's'

def ask_yes_no(question: str, default: bool = True) -> bool:
    """Pregunta sí/no"""
    default_str = "S/n" if default else "s/N"
    response = input(f"    {question} ({default_str}): ").strip().lower()
    
    if default:
        return response != 'n'
    else:
        return response == 's'

def main():
    """Función principal"""
    print_banner()
    check_root()
    show_legal_warning()
    
    # Menú interactivo
    mode = interactive_menu()
    
    if mode == 0:
        print("\n[*] Saliendo...")
        sys.exit(0)
    
    # Configuración de módulos a ejecutar
    modules_config = {
        'reconocimiento': False,
        'reconocimiento_skip_ports': False,
        'file_harvester': False,
        'router_exploit': False,
        'router_backdoor': False,
        'camera_exploit': False,
        'camera_capture_video': False,
        'service_exploit': False,
        'credential_harvest': False,
        'backdoor_manager': False,
        'report_generator': True,  # Siempre al final
    }
    
    # Configurar según el modo seleccionado
    if mode == 1:  # Full Suite
        print("\n[*] Modo: FULL PENTESTING SUITE")
        print("[*] Configurando módulos...\n")
        
        modules_config['reconocimiento'] = ask_module_execution(
            "Módulo 1", "Reconocimiento de red", True
        )
        
        if modules_config['reconocimiento']:
            modules_config['reconocimiento_skip_ports'] = not ask_yes_no(
                "¿Ejecutar escaneo de puertos? (más lento pero completo)", True
            )
        
        modules_config['file_harvester'] = ask_module_execution(
            "Módulo 2", "Descarga de archivos compartidos", True
        )
        
        modules_config['router_exploit'] = ask_module_execution(
            "Módulo 3", "Explotación de router", True
        )
        
        if modules_config['router_exploit']:
            modules_config['router_backdoor'] = ask_yes_no(
                "¿Instalar backdoor si es exitoso?", True
            )
        
        modules_config['camera_exploit'] = ask_module_execution(
            "Módulo 4", "Explotación de cámaras/DVR", True
        )
        
        if modules_config['camera_exploit']:
            modules_config['camera_capture_video'] = ask_yes_no(
                "¿Capturar video si es exitoso?", True
            )
        
        modules_config['service_exploit'] = ask_module_execution(
            "Módulo 5", "Explotación de servicios", True
        )
        
        modules_config['credential_harvest'] = ask_module_execution(
            "Módulo 6", "Recolección de credenciales", True
        )
        
        modules_config['backdoor_manager'] = ask_module_execution(
            "Módulo 7", "Instalación de backdoors", True
        )
    
    elif mode == 2:  # Manual
        print("\n[*] Modo: SELECCIÓN MANUAL")
        print("[*] Selecciona los módulos a ejecutar...\n")
        
        # Igual que modo 1
        modules_config['reconocimiento'] = ask_module_execution(
            "Módulo 1", "Reconocimiento de red", False
        )
        
        if modules_config['reconocimiento']:
            modules_config['reconocimiento_skip_ports'] = not ask_yes_no(
                "¿Ejecutar escaneo de puertos?", True
            )
        
        modules_config['file_harvester'] = ask_module_execution(
            "Módulo 2", "File Harvester", False
        )
        
        modules_config['router_exploit'] = ask_module_execution(
            "Módulo 3", "Router Exploitation", False
        )
        
        if modules_config['router_exploit']:
            modules_config['router_backdoor'] = ask_yes_no(
                "¿Instalar backdoor si es exitoso?", True
            )
        
        modules_config['camera_exploit'] = ask_module_execution(
            "Módulo 4", "Camera Exploitation", False
        )
        
        if modules_config['camera_exploit']:
            modules_config['camera_capture_video'] = ask_yes_no(
                "¿Capturar video si es exitoso?", True
            )
        
        modules_config['service_exploit'] = ask_module_execution(
            "Módulo 5", "Service Exploitation", False
        )
        
        modules_config['credential_harvest'] = ask_module_execution(
            "Módulo 6", "Credential Harvesting", False
        )
        
        modules_config['backdoor_manager'] = ask_module_execution(
            "Módulo 7", "Backdoor Manager", False
        )
    
    elif mode == 3:  # Rápido
        print("\n[*] Modo: RÁPIDO (credenciales y servicios críticos)")
        modules_config['reconocimiento'] = True
        modules_config['reconocimiento_skip_ports'] = True
        modules_config['router_exploit'] = True
        modules_config['credential_harvest'] = True
        modules_config['service_exploit'] = True
    
    elif mode == 4:  # Solo reconocimiento
        print("\n[*] Modo: SOLO RECONOCIMIENTO")
        modules_config['reconocimiento'] = True
        modules_config['reconocimiento_skip_ports'] = not ask_yes_no(
            "¿Ejecutar escaneo de puertos?", True
        )
        modules_config['report_generator'] = False
    
    elif mode == 5:  # Solo informe
        print("\n[*] Modo: SOLO GENERAR INFORME")
        print("[*] Se generará el informe consolidado con los datos existentes...\n")
        modules_config['report_generator'] = True
    
    # Ejecutar módulos configurados
    try:
        print("\n" + "="*70)
        print("  INICIANDO PENTESTING")
        print("="*70)
        
        # Crear directorios
        os.makedirs("reports", exist_ok=True)
        os.makedirs("loot/stolen_videos", exist_ok=True)
        os.makedirs("loot/router_configs", exist_ok=True)
        os.makedirs("loot/credentials", exist_ok=True)
        os.makedirs("loot/backdoors", exist_ok=True)
        
        # Variables para compartir entre módulos
        network_range = None
        router_ip = "192.168.110.1"
        camera_ip = "192.168.110.59"
        
        # MÓDULO 1: Reconocimiento
        if modules_config['reconocimiento']:
            recon = NetworkRecon(
                output_file="reports/informe_reconocimiento.json"
            )
            
            wifi_info = recon.detect_wifi_connection()
            
            if wifi_info['connected']:
                network_range = wifi_info['network_range']
                print(f"\n[✓] Red WiFi detectada: {network_range}")
                
                input("\n[!] Presiona ENTER para comenzar el escaneo o Ctrl+C para cancelar...")
                
                recon.run_full_reconnaissance(
                    quick_scan=(mode == 3),
                    skip_port_scan=modules_config['reconocimiento_skip_ports']
                )
        
        # MÓDULO 2: File Harvester
        if modules_config['file_harvester']:
            harvester = FileHarvester(
                reconnaissance_file="reports/informe_reconocimiento.json",
                output_dir="harvested_files",
                output_json="reports/informe_file_harvester.json"
            )
            
            harvester.run_harvesting(
                max_file_size=10*1024*1024,  # 10MB
                max_files_per_host=100
            )
        
        # MÓDULO 3: Router Exploitation
        if modules_config['router_exploit']:
            router_exploit = RouterExploit(
                target_ip=router_ip,
                output_dir="reports"
            )
            
            router_exploit.run_exploitation()
        
        # MÓDULO 4: Camera Exploitation
        if modules_config['camera_exploit']:
            camera_exploit = CameraExploit(
                target_ip=camera_ip,
                output_dir="reports"
            )
            
            camera_exploit.run_exploitation()
        
        # MÓDULO 5: Service Exploitation
        if modules_config['service_exploit']:
            service_exploit = ServiceExploit(
                recon_file="reports/informe_reconocimiento.json",
                output_dir="reports"
            )
            
            service_exploit.run_exploitation()
        
        # MÓDULO 6: Credential Harvesting
        if modules_config['credential_harvest']:
            credential_harvest = CredentialHarvester(
                recon_file="reports/informe_reconocimiento.json",
                output_dir="reports"
            )
            
            credential_harvest.run_harvesting()
        
        # MÓDULO 7: Backdoor Manager
        if modules_config['backdoor_manager']:
            backdoor_manager = BackdoorManager(
                output_dir="reports"
            )
            
            backdoor_manager.run_backdoor_installation()
        
        # MÓDULO 8: Report Generator
        if modules_config['report_generator']:
            report_gen = ReportGenerator(
                reports_dir="reports"
            )
            
            report_gen.generate_master_report()
        
        # Resumen final
        print("\n" + "="*70)
        print("  ✓ PENTESTING COMPLETADO")
        print("="*70)
        print("\n[✓] Todos los módulos han finalizado")
        print("\n[*] Archivos generados:")
        print("    • reports/INFORME_GENERAL_PENTESTING.json")
        print("    • reports/INFORME_EJECUTIVO.html")
        print("    • loot/ (archivos robados, videos, backdoors)")
        print("\n[*] Abre el informe HTML en tu navegador para ver los resultados")
        print("\n" + "="*70 + "\n")
    
    except KeyboardInterrupt:
        print("\n\n" + "="*70)
        print("  ⚠ PROCESO INTERRUMPIDO POR EL USUARIO")
        print("="*70)
        print("\n[*] Los resultados parciales han sido guardados")
        sys.exit(1)
    
    except Exception as e:
        print("\n\n" + "="*70)
        print("  ✗ ERROR DURANTE EL PENTESTING")
        print("="*70)
        print(f"\n[!] Error: {str(e)}")
        import traceback
        traceback.print_exc()
        sys.exit(1)

if __name__ == "__main__":
    main()
