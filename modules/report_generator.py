#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Módulo 8: Report Generator
Genera informe consolidado de todos los módulos de pentesting
"""

import json
import os
from datetime import datetime
from typing import Dict, List
from pathlib import Path

class ReportGenerator:
    """Clase para generar informe maestro consolidado"""
    
    def __init__(self, reports_dir: str = "reports"):
        """
        Inicializa el generador de informes
        
        Args:
            reports_dir: Directorio donde están los informes individuales
        """
        self.reports_dir = reports_dir
        Path(self.reports_dir).mkdir(parents=True, exist_ok=True)
        
        self.master_report = {
            "report_type": "MASTER PENTESTING REPORT",
            "generated_at": datetime.now().isoformat(),
            "version": "1.0",
            "modules_executed": [],
            "executive_summary": {},
            "detailed_findings": {},
            "statistics": {},
            "risk_score": 0,
            "critical_findings": [],
            "recommendations": []
        }
    
    def generate_master_report(self) -> Dict:
        """Genera el informe maestro consolidado"""
        print(f"\n{'='*70}")
        print(f"  MÓDULO 8: GENERANDO INFORME CONSOLIDADO")
        print(f"{'='*70}\n")
        
        # Cargar todos los informes individuales
        print(f"[*] Cargando informes individuales...")
        
        reports = {
            'reconocimiento': self._load_report('informe_reconocimiento.json') or self._load_report('../reconocimiento.json'),
            'router_exploit': self._load_report('informe_router_exploitation.json'),
            'camera_exploit': self._load_report('informe_camera_exploitation.json'),
            'service_exploit': self._load_report('informe_service_exploitation.json'),
            'credential_harvest': self._load_report('informe_credential_harvesting.json'),
            'backdoor': self._load_report('informe_backdoor_persistence.json'),
            'file_harvest': self._load_report('informe_file_harvester.json') or self._load_report('../archivos_descargados.json'),
        }
        
        # Contar módulos ejecutados
        executed_modules = [name for name, report in reports.items() if report is not None]
        self.master_report['modules_executed'] = executed_modules
        
        print(f"    [✓] Módulos cargados: {len(executed_modules)}")
        
        # Generar resumen ejecutivo
        print(f"[*] Generando resumen ejecutivo...")
        self._generate_executive_summary(reports)
        
        # Consolidar hallazgos
        print(f"[*] Consolidando hallazgos...")
        self._consolidate_findings(reports)
        
        # Calcular estadísticas
        print(f"[*] Calculando estadísticas...")
        self._calculate_statistics(reports)
        
        # Calcular score de riesgo
        print(f"[*] Calculando score de riesgo...")
        self._calculate_risk_score(reports)
        
        # Identificar hallazgos críticos
        print(f"[*] Identificando hallazgos críticos...")
        self._identify_critical_findings(reports)
        
        # Consolidar recomendaciones
        print(f"[*] Consolidando recomendaciones...")
        self._consolidate_recommendations(reports)
        
        # Guardar informe maestro
        print(f"[*] Guardando informe maestro...")
        self._save_master_report()
        
        # Generar informe HTML
        print(f"[*] Generando informe HTML ejecutivo...")
        self._generate_html_report()
        
        print(f"\n[✓✓✓] INFORME CONSOLIDADO GENERADO EXITOSAMENTE\n")
        
        return self.master_report
    
    def _load_report(self, filename: str) -> Dict:
        """Carga un informe individual"""
        try:
            filepath = os.path.join(self.reports_dir, filename)
            if not os.path.exists(filepath):
                # Intentar sin reports/
                filepath = filename
            
            with open(filepath, 'r', encoding='utf-8') as f:
                return json.load(f)
        except:
            return None
    
    def _generate_executive_summary(self, reports: Dict):
        """Genera resumen ejecutivo"""
        summary = {
            "scan_date": datetime.now().strftime("%Y-%m-%d"),
            "network_analyzed": "Unknown",
            "total_hosts": 0,
            "hosts_compromised": 0,
            "vulnerabilities_found": 0,
            "credentials_obtained": 0,
            "backdoors_installed": 0,
            "videos_captured": 0,
            "overall_status": "Unknown"
        }
        
        # Reconocimiento
        if reports['reconocimiento']:
            recon = reports['reconocimiento']
            summary['network_analyzed'] = recon.get('network_info', {}).get('range', 'Unknown')
            summary['total_hosts'] = len(recon.get('discovered_hosts', []))
        
        # Router
        if reports['router_exploit']:
            router = reports['router_exploit']
            if router.get('access_obtained'):
                summary['hosts_compromised'] += 1
            summary['vulnerabilities_found'] += len(router.get('vulnerabilities_found', []))
        
        # Cámaras
        if reports['camera_exploit']:
            camera = reports['camera_exploit']
            if camera.get('access_obtained'):
                summary['hosts_compromised'] += 1
            summary['vulnerabilities_found'] += len(camera.get('vulnerabilities_found', []))
            summary['videos_captured'] = len(camera.get('loot', {}).get('videos_captured', []))
        
        # Servicios
        if reports['service_exploit']:
            service = reports['service_exploit']
            summary['vulnerabilities_found'] += len(service.get('vulnerabilities_found', []))
        
        # Credenciales
        if reports['credential_harvest']:
            creds = reports['credential_harvest']
            summary['credentials_obtained'] = len(creds.get('credentials_found', []))
            summary['hosts_compromised'] += len(creds.get('hosts_analyzed', []))
        
        # Backdoors
        if reports['backdoor']:
            backdoor = reports['backdoor']
            summary['backdoors_installed'] = len(backdoor.get('backdoors_installed', []))
        
        # Estado general
        if summary['hosts_compromised'] > 0:
            summary['overall_status'] = 'CRITICAL - Hosts Compromised'
        elif summary['vulnerabilities_found'] > 5:
            summary['overall_status'] = 'HIGH RISK - Multiple Vulnerabilities'
        elif summary['vulnerabilities_found'] > 0:
            summary['overall_status'] = 'MEDIUM RISK - Vulnerabilities Found'
        else:
            summary['overall_status'] = 'LOW RISK'
        
        self.master_report['executive_summary'] = summary
    
    def _consolidate_findings(self, reports: Dict):
        """Consolida hallazgos de todos los módulos"""
        findings = {}
        
        for module_name, report in reports.items():
            if not report:
                continue
            
            findings[module_name] = {
                'status': report.get('status', 'Unknown'),
                'vulnerabilities': report.get('vulnerabilities_found', []),
                'actions_performed': report.get('actions_performed', []),
                'loot_obtained': report.get('loot', {})
            }
        
        self.master_report['detailed_findings'] = findings
    
    def _calculate_statistics(self, reports: Dict):
        """Calcula estadísticas generales"""
        stats = {
            'total_scan_duration': 0,
            'total_vulnerabilities': 0,
            'critical_vulnerabilities': 0,
            'high_vulnerabilities': 0,
            'medium_vulnerabilities': 0,
            'low_vulnerabilities': 0,
            'total_exploits_attempted': 0,
            'successful_exploits': 0
        }
        
        for report in reports.values():
            if not report:
                continue
            
            # Duración
            duration = report.get('duration_seconds', 0)
            if duration:
                stats['total_scan_duration'] += duration
            
            # Vulnerabilidades
            vulns = report.get('vulnerabilities_found', [])
            stats['total_vulnerabilities'] += len(vulns)
            
            for vuln in vulns:
                severity = vuln.get('severity', 'UNKNOWN').upper()
                if 'CRITICAL' in severity:
                    stats['critical_vulnerabilities'] += 1
                elif 'HIGH' in severity:
                    stats['high_vulnerabilities'] += 1
                elif 'MEDIUM' in severity:
                    stats['medium_vulnerabilities'] += 1
                elif 'LOW' in severity:
                    stats['low_vulnerabilities'] += 1
        
        self.master_report['statistics'] = stats
    
    def _calculate_risk_score(self, reports: Dict):
        """Calcula score de riesgo (0-100)"""
        score = 0
        
        stats = self.master_report['statistics']
        summary = self.master_report['executive_summary']
        
        # Vulnerabilidades críticas: 20 puntos cada una
        score += stats['critical_vulnerabilities'] * 20
        
        # Vulnerabilidades altas: 10 puntos cada una
        score += stats['high_vulnerabilities'] * 10
        
        # Vulnerabilidades medias: 5 puntos cada una
        score += stats['medium_vulnerabilities'] * 5
        
        # Hosts comprometidos: 15 puntos cada uno
        score += summary['hosts_compromised'] * 15
        
        # Backdoors instalados: 25 puntos cada uno
        score += summary['backdoors_installed'] * 25
        
        # Credenciales obtenidas: 10 puntos cada una
        score += summary['credentials_obtained'] * 10
        
        # Cap a 100
        score = min(score, 100)
        
        self.master_report['risk_score'] = score
    
    def _identify_critical_findings(self, reports: Dict):
        """Identifica hallazgos críticos"""
        critical = []
        
        # Router comprometido
        if reports['router_exploit'] and reports['router_exploit'].get('access_obtained'):
            critical.append({
                'title': 'ROUTER COMPROMETIDO',
                'severity': 'CRITICAL',
                'description': 'Se obtuvo acceso completo al router de la red',
                'impact': 'Control total del tráfico de red, acceso a credenciales WiFi, capacidad de man-in-the-middle',
                'module': 'Router Exploitation'
            })
        
        # Cámaras comprometidas
        if reports['camera_exploit'] and reports['camera_exploit'].get('access_obtained'):
            critical.append({
                'title': 'SISTEMA DE CÁMARAS COMPROMETIDO',
                'severity': 'CRITICAL',
                'description': 'Se obtuvo acceso a cámaras de seguridad y grabaciones',
                'impact': 'Privacidad comprometida, posible vigilancia por atacante, información sensible expuesta',
                'module': 'Camera Exploitation'
            })
        
        # Backdoors instalados
        if reports['backdoor']:
            backdoors = len(reports['backdoor'].get('backdoors_installed', []))
            if backdoors > 0:
                critical.append({
                    'title': f'BACKDOORS INSTALADOS ({backdoors})',
                    'severity': 'CRITICAL',
                    'description': f'Se instalaron {backdoors} backdoors con persistencia en la red',
                    'impact': 'Acceso persistente para atacante, difícil de detectar y remover',
                    'module': 'Backdoor Manager'
                })
        
        # Credenciales comprometidas
        if reports['credential_harvest']:
            creds = len(reports['credential_harvest'].get('credentials_found', []))
            if creds > 5:
                critical.append({
                    'title': f'CREDENCIALES MASIVAMENTE COMPROMETIDAS ({creds})',
                    'severity': 'CRITICAL',
                    'description': f'Se obtuvieron {creds} conjuntos de credenciales válidas',
                    'impact': 'Movimiento lateral posible, acceso a múltiples sistemas',
                    'module': 'Credential Harvesting'
                })
        
        self.master_report['critical_findings'] = critical
    
    def _consolidate_recommendations(self, reports: Dict):
        """Consolida recomendaciones prioritarias"""
        all_recommendations = []
        
        # Recomendaciones críticas prioritarias
        priority_recommendations = [
            "URGENTE: Cambiar TODAS las credenciales por defecto inmediatamente",
            "URGENTE: Remover todos los backdoors instalados durante la prueba",
            "URGENTE: Actualizar firmware del router a la última versión",
            "CRÍTICO: Deshabilitar acceso remoto a servicios críticos desde Internet",
            "CRÍTICO: Implementar autenticación de múltiples factores",
        ]
        
        all_recommendations.extend(priority_recommendations)
        
        # Agregar recomendaciones de cada módulo (sin duplicados)
        seen = set(priority_recommendations)
        
        for report in reports.values():
            if not report:
                continue
            
            recs = report.get('recommendations', [])
            for rec in recs[:5]:  # Top 5 de cada módulo
                if rec not in seen:
                    all_recommendations.append(rec)
                    seen.add(rec)
        
        self.master_report['recommendations'] = all_recommendations[:20]  # Top 20 recomendaciones
    
    def _save_master_report(self):
        """Guarda el informe maestro"""
        output_file = os.path.join(self.reports_dir, "INFORME_GENERAL_PENTESTING.json")
        
        with open(output_file, 'w', encoding='utf-8') as f:
            json.dump(self.master_report, f, indent=4, ensure_ascii=False)
        
        print(f"    [✓] Informe JSON: {output_file}")
    
    def _generate_html_report(self):
        """Genera informe HTML ejecutivo"""
        output_file = os.path.join(self.reports_dir, "INFORME_EJECUTIVO.html")
        
        summary = self.master_report['executive_summary']
        stats = self.master_report['statistics']
        risk_score = self.master_report['risk_score']
        
        # Determinar color de riesgo
        if risk_score >= 70:
            risk_color = '#dc3545'
            risk_level = 'CRÍTICO'
        elif risk_score >= 40:
            risk_color = '#fd7e14'
            risk_level = 'ALTO'
        elif risk_score >= 20:
            risk_color = '#ffc107'
            risk_level = 'MEDIO'
        else:
            risk_color = '#28a745'
            risk_level = 'BAJO'
        
        html_content = f"""<!DOCTYPE html>
<html lang="es">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Informe Ejecutivo de Pentesting</title>
    <style>
        body {{
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            margin: 0;
            padding: 20px;
            background-color: #f5f5f5;
        }}
        .container {{
            max-width: 1200px;
            margin: 0 auto;
            background-color: white;
            padding: 40px;
            box-shadow: 0 0 20px rgba(0,0,0,0.1);
        }}
        .header {{
            text-align: center;
            border-bottom: 4px solid #333;
            padding-bottom: 20px;
            margin-bottom: 40px;
        }}
        .header h1 {{
            margin: 0;
            color: #333;
        }}
        .risk-score {{
            text-align: center;
            padding: 30px;
            margin: 30px 0;
            background-color: {risk_color};
            color: white;
            border-radius: 10px;
        }}
        .risk-score h2 {{
            margin: 0;
            font-size: 48px;
        }}
        .summary-grid {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(250px, 1fr));
            gap: 20px;
            margin: 30px 0;
        }}
        .summary-card {{
            padding: 20px;
            background-color: #f8f9fa;
            border-left: 4px solid #007bff;
            border-radius: 5px;
        }}
        .summary-card h3 {{
            margin: 0 0 10px 0;
            color: #333;
        }}
        .summary-card p {{
            margin: 0;
            font-size: 32px;
            font-weight: bold;
            color: #007bff;
        }}
        .critical-findings {{
            margin: 30px 0;
        }}
        .finding-item {{
            padding: 20px;
            margin: 15px 0;
            background-color: #fff3cd;
            border-left: 5px solid #ffc107;
            border-radius: 5px;
        }}
        .finding-item.critical {{
            background-color: #f8d7da;
            border-left-color: #dc3545;
        }}
        .finding-item h4 {{
            margin: 0 0 10px 0;
            color: #333;
        }}
        .recommendations {{
            margin: 30px 0;
        }}
        .recommendations li {{
            margin: 10px 0;
            padding: 10px;
            background-color: #d1ecf1;
            border-left: 4px solid #0c5460;
        }}
        .footer {{
            margin-top: 40px;
            padding-top: 20px;
            border-top: 2px solid #ddd;
            text-align: center;
            color: #666;
        }}
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>INFORME EJECUTIVO DE PENTESTING</h1>
            <p>Red Recognition - Análisis de Seguridad de Red</p>
            <p>Fecha: {summary['scan_date']}</p>
        </div>
        
        <div class="risk-score">
            <h2>SCORE DE RIESGO: {risk_score}/100</h2>
            <p>Nivel: {risk_level}</p>
        </div>
        
        <h2>Resumen Ejecutivo</h2>
        <div class="summary-grid">
            <div class="summary-card">
                <h3>Red Analizada</h3>
                <p>{summary['network_analyzed']}</p>
            </div>
            <div class="summary-card">
                <h3>Hosts Totales</h3>
                <p>{summary['total_hosts']}</p>
            </div>
            <div class="summary-card">
                <h3>Hosts Comprometidos</h3>
                <p style="color: #dc3545;">{summary['hosts_compromised']}</p>
            </div>
            <div class="summary-card">
                <h3>Vulnerabilidades</h3>
                <p style="color: #fd7e14;">{summary['vulnerabilities_found']}</p>
            </div>
            <div class="summary-card">
                <h3>Credenciales Obtenidas</h3>
                <p style="color: #dc3545;">{summary['credentials_obtained']}</p>
            </div>
            <div class="summary-card">
                <h3>Backdoors Instalados</h3>
                <p style="color: #dc3545;">{summary['backdoors_installed']}</p>
            </div>
        </div>
        
        <div class="critical-findings">
            <h2>Hallazgos Críticos</h2>
"""
        
        for finding in self.master_report['critical_findings']:
            html_content += f"""
            <div class="finding-item critical">
                <h4>⚠️ {finding['title']}</h4>
                <p><strong>Descripción:</strong> {finding['description']}</p>
                <p><strong>Impacto:</strong> {finding['impact']}</p>
                <p><strong>Módulo:</strong> {finding['module']}</p>
            </div>
"""
        
        html_content += """
        </div>
        
        <div class="recommendations">
            <h2>Recomendaciones Prioritarias</h2>
            <ol>
"""
        
        for rec in self.master_report['recommendations'][:10]:
            html_content += f"                <li>{rec}</li>\n"
        
        html_content += f"""
            </ol>
        </div>
        
        <div class="footer">
            <p>Generado por Red Recognition v1.0</p>
            <p>{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>
        </div>
    </div>
</body>
</html>
"""
        
        with open(output_file, 'w', encoding='utf-8') as f:
            f.write(html_content)
        
        print(f"    [✓] Informe HTML: {output_file}")

