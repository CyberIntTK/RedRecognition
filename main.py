#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Script Principal de Reconocimiento de Red
Herramienta modular para pentesting y análisis de redes WiFi
Optimizado para Kali Linux
"""

import os
import sys
import json
import argparse
from datetime import datetime
from modules.network_recon import NetworkRecon

def print_banner():
    """Muestra el banner de la aplicación"""
    banner = """
    ╔═══════════════════════════════════════════════════════════╗
    ║           RED RECOGNITION - NETWORK SCANNER               ║
    ║         Herramienta de Reconocimiento de Red WiFi         ║
    ║                  Optimizado para Kali Linux               ║
    ╚═══════════════════════════════════════════════════════════╝
    """
    print(banner)

def check_root():
    """Verifica si el script se está ejecutando como root"""
    if os.geteuid() != 0:
        print("╔════════════════════════════════════════════════════════════╗")
        print("║                    ⚠️  ADVERTENCIA  ⚠️                      ║")
        print("║                                                            ║")
        print("║  Este script requiere privilegios de root para funcionar  ║")
        print("║  correctamente y obtener todos los datos de la red.       ║")
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

def main():
    """Función principal del script"""
    print_banner()
    
    # Verificar permisos de root (solo en Linux)
    if sys.platform == 'linux':
        check_root()
    
    # Configurar argumentos de línea de comandos
    parser = argparse.ArgumentParser(
        description='Herramienta modular de reconocimiento de red para pentesting',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Ejemplos de uso:
  sudo python3 main.py                    # Escaneo completo automático
  sudo python3 main.py --quick            # Escaneo rápido
  sudo python3 main.py --no-port-scan     # Solo descubrir hosts
  sudo python3 main.py -o resultado.json  # Archivo de salida personalizado
  sudo python3 main.py -i wlan0           # Interfaz específica
  sudo python3 main.py -r 192.168.1.0/24  # Rango personalizado
        """
    )
    parser.add_argument(
        '-o', '--output',
        default='reconocimiento.json',
        help='Archivo de salida JSON (default: reconocimiento.json)'
    )
    parser.add_argument(
        '-i', '--interface',
        default=None,
        help='Interfaz de red a utilizar (default: auto-detectar WiFi activa)'
    )
    parser.add_argument(
        '-r', '--range',
        default=None,
        help='Rango de red personalizado (ej: 192.168.1.0/24)'
    )
    parser.add_argument(
        '--quick',
        action='store_true',
        help='Escaneo rápido (top 100 puertos más comunes)'
    )
    parser.add_argument(
        '--no-port-scan',
        action='store_true',
        help='Desactivar escaneo de puertos (solo descubrir hosts)'
    )
    parser.add_argument(
        '--show-wifi-only',
        action='store_true',
        help='Solo mostrar información de la red WiFi y salir'
    )
    
    args = parser.parse_args()
    
    try:
        # Inicializar el módulo de reconocimiento
        print(f"[*] Inicializando módulo de reconocimiento...")
        print(f"[*] Archivo de salida: {args.output}\n")
        
        # Módulo 1: Reconocimiento de Red
        recon = NetworkRecon(
            output_file=args.output,
            interface=args.interface,
            network_range=args.range
        )
        
        # Mostrar información de la red WiFi conectada
        print("═" * 70)
        print("  INFORMACIÓN DE LA RED WiFi CONECTADA")
        print("═" * 70)
        
        wifi_info = recon.detect_wifi_connection()
        
        if not wifi_info['connected']:
            print("\n[!] ERROR: No se detectó conexión WiFi activa")
            print("[!] Asegúrate de estar conectado a una red WiFi y vuelve a intentar")
            sys.exit(1)
        
        print(f"\n[✓] Conexión WiFi detectada:")
        print(f"    Interfaz:        {wifi_info['interface']}")
        print(f"    SSID:            {wifi_info['ssid']}")
        print(f"    BSSID:           {wifi_info['bssid']}")
        print(f"    Frecuencia:      {wifi_info['frequency']}")
        print(f"    Canal:           {wifi_info['channel']}")
        print(f"    Calidad:         {wifi_info['signal_quality']}")
        print(f"    Potencia:        {wifi_info['signal_level']}")
        print(f"    IP Local:        {wifi_info['ip_address']}")
        print(f"    Máscara:         {wifi_info['netmask']}")
        print(f"    Gateway:         {wifi_info['gateway']}")
        print(f"    Rango de Red:    {wifi_info['network_range']}")
        
        print("\n" + "═" * 70)
        
        # Si solo se quiere ver la info WiFi, salir aquí
        if args.show_wifi_only:
            print("\n[*] Modo --show-wifi-only activado. Saliendo...")
            sys.exit(0)
        
        # Confirmar antes de comenzar el escaneo
        print("\n[*] Se va a escanear la red: " + wifi_info['network_range'])
        if not args.quick and not args.no_port_scan:
            print("[*] Tipo de escaneo: COMPLETO (puede tardar 15-30 minutos)")
        elif args.quick:
            print("[*] Tipo de escaneo: RÁPIDO (5-10 minutos aprox.)")
        elif args.no_port_scan:
            print("[*] Tipo de escaneo: SOLO HOSTS (1-2 minutos aprox.)")
        
        print("\n[!] El escaneo puede ser detectado por sistemas de seguridad")
        print("[!] Asegúrate de tener autorización para escanear esta red")
        print("[!] Presiona Ctrl+C en cualquier momento para detener\n")
        
        input("Presiona ENTER para comenzar el escaneo o Ctrl+C para cancelar...")
        print()
        
        # Ejecutar el reconocimiento completo
        recon.run_full_reconnaissance(
            quick_scan=args.quick,
            skip_port_scan=args.no_port_scan
        )
        
        print("\n" + "═" * 70)
        print("  ✓ RECONOCIMIENTO COMPLETADO EXITOSAMENTE")
        print("═" * 70)
        print(f"\n[✓] Resultados guardados en: {args.output}")
        print(f"[✓] Puedes visualizar el archivo JSON con:")
        print(f"    cat {args.output} | python3 -m json.tool")
        print(f"    o simplemente: cat {args.output}\n")
        
    except KeyboardInterrupt:
        print("\n\n" + "═" * 70)
        print("  ⚠ PROCESO INTERRUMPIDO POR EL USUARIO")
        print("═" * 70)
        print(f"\n[*] Los resultados parciales han sido guardados en: {args.output}")
        print(f"[*] Puedes revisar los datos recopilados hasta el momento\n")
        sys.exit(1)
    
    except Exception as e:
        print("\n\n" + "═" * 70)
        print("  ✗ ERROR DURANTE EL RECONOCIMIENTO")
        print("═" * 70)
        print(f"\n[!] Error: {str(e)}")
        print(f"[*] Los resultados parciales han sido guardados en: {args.output}\n")
        import traceback
        traceback.print_exc()
        sys.exit(1)

if __name__ == "__main__":
    main()

