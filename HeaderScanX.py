import sys
import requests
import re
import json
import time
import urllib.parse
from datetime import datetime
from PyQt5.QtWidgets import (QApplication, QMainWindow, QWidget, QVBoxLayout, 
                            QHBoxLayout, QLabel, QLineEdit, QPushButton, 
                            QTextEdit, QProgressBar, QGroupBox, QFrame, 
                            QFileDialog, QMessageBox, QCheckBox)
from PyQt5.QtCore import Qt, QThread, pyqtSignal, QPropertyAnimation, QEasingCurve, QRect
from PyQt5.QtGui import QFont, QFontDatabase, QTextCursor

VT_API_KEY = "965d9e6358ee0adbb2dd8c0b405dfa8cb5763e1313732282630a57894ea5a405"

class VirusTotalScanner:
    def __init__(self, api_key):
        self.api_key = api_key
        self.base_url = "https://www.virustotal.com/api/v3"
        self.headers = {
            "x-apikey": self.api_key,
            "Accept": "application/json"
        }
    
    def check_url_safety(self, url):
        try:
            # Отправляем URL на сканирование
            scan_url = f"{self.base_url}/urls"
            data = {"url": url}
            
            response = requests.post(scan_url, headers=self.headers, data=data)
            
            if response.status_code == 200:
                scan_data = response.json()
                url_id = scan_data.get("data", {}).get("id", "")
                
                if url_id:
                    # Ждём завершения анализа
                    time.sleep(5)
                    
                    # Получаем результат
                    report_url = f"{self.base_url}/analyses/{url_id}"
                    response = requests.get(report_url, headers=self.headers)
                    
                    if response.status_code == 200:
                        report_data = response.json()
                        attributes = report_data.get("data", {}).get("attributes", {})
                        stats = attributes.get("stats", {})
                        
                        malicious = stats.get("malicious", 0)
                        suspicious = stats.get("suspicious", 0)
                        
                        return {
                            "success": True,
                            "url": url,
                            "malicious": malicious,
                            "suspicious": suspicious,
                            "harmless": stats.get("harmless", 0),
                            "undetected": stats.get("undetected", 0),
                            "total_scans": sum(stats.values()),
                            "reputation": 0,
                            "is_safe": malicious == 0 and suspicious == 0
                        }
            
            return {"error": "Не удалось получить результат от VirusTotal. Попробуйте позже."}
            
        except requests.exceptions.RequestException as e:
            return {"error": f"Ошибка сети: {str(e)}"}
        except Exception as e:
            return {"error": f"Ошибка: {str(e)}"}

class ScannerThread(QThread):
    update_signal = pyqtSignal(str, dict, int)
    vt_signal = pyqtSignal(dict)
    progress_signal = pyqtSignal(int)
    error_signal = pyqtSignal(str)
    finished_signal = pyqtSignal()
    
    def __init__(self, url, vt_enabled):
        super().__init__()
        self.url = url
        self.vt_enabled = vt_enabled
    
    def analyze_security_headers(self, headers):
        results = {
            'csp': {'status': False, 'details': '', 'risk': ''},
            'hsts': {'status': False, 'details': '', 'risk': ''},
            'xfo': {'status': False, 'details': '', 'risk': ''},
            'xss': {'status': False, 'details': '', 'risk': ''},
            'xcto': {'status': False, 'details': '', 'risk': ''},
            'rp': {'status': False, 'details': '', 'risk': ''},
            'pp': {'status': False, 'details': '', 'risk': ''}
        }
        
        csp = headers.get('Content-Security-Policy', headers.get('Content-Security-Policy-Report-Only', ''))
        if csp:
            results['csp']['status'] = True
            risks = []
            if "'unsafe-inline'" in csp:
                risks.append("unsafe-inline")
            if "'unsafe-eval'" in csp:
                risks.append("unsafe-eval")
            if risks:
                results['csp']['risk'] = f"⚠️ Обнаружены опасные директивы: {', '.join(risks)}"
                results['csp']['details'] = f"CSP активен, но содержит {', '.join(risks)}"
            else:
                results['csp']['details'] = "CSP правильно настроен"
        else:
            results['csp']['risk'] = "❌ Высокий риск XSS-атак"
            results['csp']['details'] = "Отсутствует защита от межсайтового скриптинга"
        
        hsts = headers.get('Strict-Transport-Security', '')
        if hsts:
            results['hsts']['status'] = True
            max_age = re.search(r'max-age=(\d+)', hsts)
            if max_age and int(max_age.group(1)) >= 31536000:
                results['hsts']['details'] = "HSTS настроен корректно (max-age >= 1 год)"
            else:
                results['hsts']['risk'] = "⚠️ Малый max-age"
                results['hsts']['details'] = "Рекомендуется установить max-age=31536000"
        else:
            results['hsts']['risk'] = "❌ Риск SSL stripping атак"
            results['hsts']['details'] = "Отсутствует принудительное HTTPS соединение"
        
        xfo = headers.get('X-Frame-Options', '')
        if xfo:
            results['xfo']['status'] = True
            if xfo.upper() in ['DENY', 'SAMEORIGIN']:
                results['xfo']['details'] = f"Защита от кликджекинга активна ({xfo})"
        else:
            results['xfo']['risk'] = "❌ Риск кликджекинга"
            results['xfo']['details'] = "Сайт может быть встроен в frame/frame"
        
        xss = headers.get('X-XSS-Protection', '')
        if xss:
            results['xss']['status'] = True
            results['xss']['details'] = f"XSS фильтр браузера активен ({xss})"
        else:
            results['xss']['risk'] = "⚠️ Средний риск"
            results['xss']['details'] = "Старый браузерный XSS фильтр отключен"
        
        xcto = headers.get('X-Content-Type-Options', '')
        if xcto and xcto.lower() == 'nosniff':
            results['xcto']['status'] = True
            results['xcto']['details'] = "Защита от MIME-sniffing активна"
        else:
            results['xcto']['risk'] = "⚠️ Риск MIME-атак"
            results['xcto']['details'] = "Браузер может определять MIME-типы автоматически"
        
        rp = headers.get('Referrer-Policy', '')
        if rp:
            results['rp']['status'] = True
            results['rp']['details'] = f"Referrer политика: {rp}"
        else:
            results['rp']['risk'] = "⚠️ Утечка referrer информации"
            results['rp']['details'] = "Рекомендуется strict-origin-when-cross-origin"
        
        pp = headers.get('Permissions-Policy', '')
        if pp:
            results['pp']['status'] = True
            results['pp']['details'] = f"Ограничены API: {pp[:60]}..."
        else:
            results['pp']['details'] = "Не ограничены возможности браузера"
        
        return results
    
    def run(self):
        try:
            self.progress_signal.emit(10)
            headers = {
                'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
            }
            response = requests.get(self.url, timeout=15, verify=False, allow_redirects=True, headers=headers)
            self.progress_signal.emit(50)
            
            headers_dict = response.headers
            analysis = self.analyze_security_headers(headers_dict)
            self.progress_signal.emit(70)
            
            self.update_signal.emit(self.url, analysis, response.status_code)
            
            if self.vt_enabled and VT_API_KEY:
                self.progress_signal.emit(75)
                vt_scanner = VirusTotalScanner(VT_API_KEY)
                vt_results = vt_scanner.check_url_safety(self.url)
                self.vt_signal.emit(vt_results)
            
            self.progress_signal.emit(100)
            
        except requests.exceptions.RequestException as e:
            self.error_signal.emit(str(e))
            self.progress_signal.emit(0)
        finally:
            self.finished_signal.emit()

class ModernButton(QPushButton):
    def __init__(self, text, parent=None):
        super().__init__(text, parent)
        self.setCursor(Qt.PointingHandCursor)
        
    def enterEvent(self, event):
        self.animate_scale(1.05)
        super().enterEvent(event)
        
    def leaveEvent(self, event):
        self.animate_scale(1.0)
        super().leaveEvent(event)
        
    def animate_scale(self, scale):
        anim = QPropertyAnimation(self, b"geometry")
        anim.setDuration(150)
        anim.setEasingCurve(QEasingCurve.OutCubic)
        geom = self.geometry()
        center = geom.center()
        new_width = int(geom.width() * scale)
        new_height = int(geom.height() * scale)
        new_geom = QRect(center.x() - new_width//2, center.y() - new_height//2, new_width, new_height)
        anim.setEndValue(new_geom)
        anim.start()

class HeaderScanX(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("HeaderScanX v3.0 - Advanced Security Scanner with VirusTotal")
        self.setGeometry(100, 100, 1400, 900)
        
        self.last_results = None
        self.last_url = None
        self.last_analysis = None
        self.last_status_code = None
        self.last_vt_results = None
        self.results_ready = False
        
        font_family = "Courier New"
        
        self.setStyleSheet(f"""
            QMainWindow {{
                background: qlineargradient(x1:0, y1:0, x2:1, y2:1,
                    stop:0 #0a0e27, stop:0.5 #1a1f3a, stop:1 #0a0e27);
            }}
            QLabel {{
                color: #a0f0ff;
                font-family: '{font_family}', monospace;
                font-size: 12px;
            }}
            QLineEdit {{
                background-color: rgba(10, 20, 40, 0.8);
                color: #4af0ff;
                border: 1px solid #2a6f8f;
                border-radius: 8px;
                font-family: '{font_family}', monospace;
                font-size: 14px;
                padding: 10px;
            }}
            QLineEdit:focus {{
                border: 1px solid #4af0ff;
                background-color: rgba(10, 20, 40, 0.9);
            }}
            QPushButton {{
                background: qlineargradient(x1:0, y1:0, x2:0, y2:1,
                    stop:0 #2a6f8f, stop:1 #1a4f6f);
                color: #ffffff;
                border: none;
                border-radius: 8px;
                font-family: '{font_family}', monospace;
                font-size: 13px;
                font-weight: bold;
                padding: 10px 20px;
            }}
            QPushButton:hover {{
                background: qlineargradient(x1:0, y1:0, x2:0, y2:1,
                    stop:0 #4af0ff, stop:1 #2a6f8f);
                color: #0a0e27;
            }}
            QPushButton:pressed {{
                padding-top: 12px;
                padding-bottom: 8px;
            }}
            QTextEdit {{
                background-color: rgba(5, 10, 20, 0.9);
                color: #b0f0ff;
                border: 1px solid #2a6f8f;
                border-radius: 8px;
                font-family: '{font_family}', monospace;
                font-size: 11px;
                padding: 10px;
            }}
            QProgressBar {{
                border: none;
                border-radius: 10px;
                background-color: rgba(20, 30, 50, 0.5);
                text-align: center;
                color: white;
                font-weight: bold;
                height: 20px;
            }}
            QProgressBar::chunk {{
                background: qlineargradient(x1:0, y1:0, x2:1, y2:0,
                    stop:0 #2a6f8f, stop:0.5 #4af0ff, stop:1 #2a6f8f);
                border-radius: 10px;
            }}
            QGroupBox {{
                color: #4af0ff;
                border: 1px solid #2a6f8f;
                border-radius: 10px;
                margin-top: 10px;
                font-family: '{font_family}', monospace;
                font-weight: bold;
                padding-top: 10px;
            }}
            QGroupBox::title {{
                subcontrol-origin: margin;
                left: 15px;
                padding: 0 10px;
                color: #4af0ff;
            }}
            QCheckBox {{
                color: #a0f0ff;
                font-family: '{font_family}', monospace;
                font-size: 12px;
            }}
        """)
        
        central_widget = QWidget()
        self.setCentralWidget(central_widget)
        main_layout = QVBoxLayout(central_widget)
        main_layout.setSpacing(15)
        main_layout.setContentsMargins(20, 20, 20, 20)
        
        header_frame = QFrame()
        header_frame.setStyleSheet("""
            QFrame {
                background: qlineargradient(x1:0, y1:0, x2:1, y2:0,
                    stop:0 rgba(42, 111, 143, 0.2), stop:1 rgba(74, 240, 255, 0.1));
                border-radius: 15px;
                padding: 15px;
            }
        """)
        header_layout = QVBoxLayout(header_frame)
        
        ascii_title = QLabel("""
╔═══════════════════════════════════════════════════════════════════════════════════════════╗
║  ██╗  ██╗███████╗ █████╗ ██████╗ ███████╗██████╗ ███████╗ ██████╗  █████╗ ███╗   ██╗██╗  ██╗
║  ██║  ██║██╔════╝██╔══██╗██╔══██╗██╔════╝██╔══██╗██╔════╝██╔════╝ ██╔══██╗████╗  ██║╚██╗██╔╝
║  ███████║█████╗  ███████║██║  ██║█████╗  ██████╔╝███████╗██║  ███╗███████║██╔██╗ ██║ ╚███╔╝ 
║  ██╔══██║██╔══╝  ██╔══██║██║  ██║██╔══╝  ██╔══██╗╚════██║██║   ██║██╔══██║██║╚██╗██║ ██╔██╗ 
║  ██║  ██║███████╗██║  ██║██████╔╝███████╗██║  ██║███████║╚██████╔╝██║  ██║██║ ╚████║██╔╝ ██╗
║  ╚═╝  ╚═╝╚══════╝╚═╝  ╚═╝╚═════╝ ╚══════╝╚═╝  ╚═╝╚══════╝ ╚═════╝ ╚═╝  ╚═╝╚═╝  ╚═══╝╚═╝  ╚═╝
║                                                                                           ║
║                    Advanced Security Header Scanner v3.0 with VirusTotal                  ║
╚═══════════════════════════════════════════════════════════════════════════════════════════╝
        """)
        ascii_title.setFont(QFont("Courier New", 8))
        ascii_title.setAlignment(Qt.AlignCenter)
        header_layout.addWidget(ascii_title)
        
        main_layout.addWidget(header_frame)
        
        input_group = QGroupBox("🎯 TARGET ACQUISITION")
        input_layout = QVBoxLayout()
        
        url_layout = QHBoxLayout()
        prompt_label = QLabel("⟫")
        prompt_label.setFont(QFont(font_family, 18, QFont.Bold))
        prompt_label.setStyleSheet("color: #4af0ff;")
        
        self.url_input = QLineEdit()
        self.url_input.setPlaceholderText("https://example.com")
        self.url_input.returnPressed.connect(self.start_scan)
        
        self.scan_btn = ModernButton("🚀 SCAN TARGET")
        self.save_btn = ModernButton("💾 SAVE REPORT")
        self.clear_btn = ModernButton("🗑️ CLEAR OUTPUT")
        
        self.scan_btn.clicked.connect(self.start_scan)
        self.save_btn.clicked.connect(self.save_report)
        self.clear_btn.clicked.connect(self.clear_output)
        
        self.save_btn.setEnabled(False)
        
        url_layout.addWidget(prompt_label)
        url_layout.addWidget(self.url_input)
        url_layout.addWidget(self.scan_btn)
        url_layout.addWidget(self.save_btn)
        url_layout.addWidget(self.clear_btn)
        
        vt_layout = QHBoxLayout()
        self.vt_checkbox = QCheckBox("🔍 Включить проверку VirusTotal (репутация URL)")
        self.vt_checkbox.setChecked(True)
        
        vt_layout.addWidget(self.vt_checkbox)
        vt_layout.addStretch()
        
        input_layout.addLayout(url_layout)
        input_layout.addLayout(vt_layout)
        input_group.setLayout(input_layout)
        main_layout.addWidget(input_group)
        
        self.progress = QProgressBar()
        self.progress.setVisible(False)
        main_layout.addWidget(self.progress)
        
        output_group = QGroupBox("📊 SCAN RESULTS")
        output_layout = QVBoxLayout()
        
        self.output_text = QTextEdit()
        self.output_text.setReadOnly(True)
        self.output_text.setLineWrapMode(QTextEdit.WidgetWidth)
        
        self.status_label = QLabel("🟢 SYSTEM READY • Waiting for target input")
        self.status_label.setStyleSheet("""
            QLabel {
                background: rgba(42, 111, 143, 0.2);
                border-radius: 5px;
                padding: 8px;
                font-size: 11px;
            }
        """)
        
        output_layout.addWidget(self.output_text)
        output_layout.addWidget(self.status_label)
        output_group.setLayout(output_layout)
        main_layout.addWidget(output_group)
        
        self.append_welcome()
    
    def append_welcome(self):
        welcome = """
╔══════════════════════════════════════════════════════════════════════════════╗
║                         WELCOME TO HEADERSCANX v3.0                          ║
╠══════════════════════════════════════════════════════════════════════════════╣
║  • Advanced security header analysis for web applications                   ║
║  • Real-time vulnerability assessment                                       ║
║  • Comprehensive security scoring system                                    ║
║  • VirusTotal integration for URL reputation check                          ║
║  • Detailed recommendations for improvement                                 ║
╠══════════════════════════════════════════════════════════════════════════════╣
║  HOW TO USE:                                                                ║
║  1. Enter target URL (http:// or https://)                                 ║
║  2. Enable/disable VirusTotal check (optional)                             ║
║  3. Click "SCAN TARGET" or press ENTER                                     ║
║  4. Analyze the security report                                            ║
║  5. Click "SAVE REPORT" to export results (TXT, JSON, or HTML)             ║
╠══════════════════════════════════════════════════════════════════════════════╣
║  EXAMPLE: https://google.com | https://github.com | https://cloudflare.com ║
╚══════════════════════════════════════════════════════════════════════════════╝

"""
        self.output_text.setText(welcome)
    
    def calculate_score(self, analysis):
        if analysis is None:
            return 0, "UNKNOWN", "❓"
        headers_status = [v['status'] for v in analysis.values()]
        total = len(headers_status)
        passed = sum(headers_status)
        score = int((passed / total) * 100) if total > 0 else 0
        
        if score >= 90:
            rating = "EXCELLENT"
            rating_symbol = "🏆"
        elif score >= 70:
            rating = "GOOD"
            rating_symbol = "✅"
        elif score >= 50:
            rating = "FAIR"
            rating_symbol = "⚠️"
        elif score >= 30:
            rating = "POOR"
            rating_symbol = "⚠️"
        else:
            rating = "CRITICAL"
            rating_symbol = "❌"
        
        return score, rating, rating_symbol
    
    def format_results(self, url, analysis, status_code, vt_results=None):
        score, rating, rating_symbol = self.calculate_score(analysis)
        
        result = f"""
{'═'*95}
📡 SCAN REPORT • {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
{'═'*95}

┌─ TARGET INFORMATION
│  URL: {url}
│  STATUS: {status_code} ✓
│
└─ SECURITY HEADERS ANALYSIS

"""
        
        headers_info = [
            ('Content-Security-Policy', 'csp', '🛡️'),
            ('Strict-Transport-Security', 'hsts', '🔒'),
            ('X-Frame-Options', 'xfo', '🖼️'),
            ('X-XSS-Protection', 'xss', '⚡'),
            ('X-Content-Type-Options', 'xcto', '📄'),
            ('Referrer-Policy', 'rp', '🔗'),
            ('Permissions-Policy', 'pp', '🎯')
        ]
        
        if analysis:
            for display_name, key, icon in headers_info:
                data = analysis.get(key, {})
                if data.get('status', False):
                    status_icon = "✅"
                    status_text = "CONFIGURED"
                else:
                    status_icon = "❌"
                    status_text = "MISSING"
                
                result += f"""
┌─ {icon} {display_name}
│  Status: {status_icon} {status_text}
│  Analysis: {data.get('details', 'Нет данных')}"""
                
                if data.get('risk'):
                    result += f"""
│  Risk: {data['risk']}"""
        else:
            result += "\n│  ⚠️ Нет данных об анализа заголовков\n"
        
        if vt_results and vt_results.get('success'):
            status_icon = "✅" if vt_results['is_safe'] else "❌"
            status_text = "БЕЗОПАСНО" if vt_results['is_safe'] else "ОПАСНО"
            
            result += f"""

{'═'*95}
🔍 VIRUSTOTAL АНАЛИЗ РЕПУТАЦИИ
{'═'*95}

┌─ Статус: {status_icon} {status_text}
│  Вредоносные детекты: {vt_results['malicious']}
│  Подозрительные: {vt_results['suspicious']}
│  Безвредные: {vt_results['harmless']}
│  Не обнаружено: {vt_results['undetected']}
│  Всего проверок: {vt_results['total_scans']}
│  Рейтинг репутации: {vt_results['reputation']}
"""
        elif vt_results and vt_results.get('error'):
            result += f"""

{'═'*95}
🔍 VIRUSTOTAL АНАЛИЗ
{'═'*95}

┌─ ⚠️ Ошибка: {vt_results['error']}
"""
        
        result += f"""

{'═'*95}
📊 SECURITY SCORE
{'═'*95}

Score: {score}/100
Rating: {rating_symbol} {rating}

Headers configured: {sum(1 for v in analysis.values() if v['status']) if analysis else 0}/{len(analysis) if analysis else 7}

{'═'*95}
💡 RECOMMENDATIONS
{'═'*95}"""
        
        recommendations_added = False
        if analysis:
            if not analysis.get('csp', {}).get('status', False):
                result += "\n  • Implement Content-Security-Policy header to prevent XSS attacks"
                recommendations_added = True
            if not analysis.get('hsts', {}).get('status', False):
                result += "\n  • Enable HSTS with max-age=31536000 and includeSubDomains"
                recommendations_added = True
            if not analysis.get('xfo', {}).get('status', False):
                result += "\n  • Add X-Frame-Options: DENY to prevent clickjacking"
                recommendations_added = True
            if not analysis.get('xcto', {}).get('status', False):
                result += "\n  • Set X-Content-Type-Options: nosniff"
                recommendations_added = True
            if not analysis.get('rp', {}).get('status', False):
                result += "\n  • Configure Referrer-Policy: strict-origin-when-cross-origin"
                recommendations_added = True
        
        if vt_results and vt_results.get('success') and not vt_results['is_safe']:
            result += "\n  • ⚠️ ВНИМАНИЕ: VirusTotal обнаружил угрозы! Проверьте сайт на вредоносное ПО"
            recommendations_added = True
            
        if not recommendations_added:
            result += "\n  ✓ All critical security headers are properly configured!"
        
        result += "\n\n" + "═"*95 + "\n"
        
        return result
    
    def save_report(self):
        if not self.last_results:
            QMessageBox.warning(self, "No Data", "No scan results to save. Please run a scan first.")
            return
        
        file_path, selected_filter = QFileDialog.getSaveFileName(
            self,
            "Save Security Report",
            f"security_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}",
            "Text Files (*.txt);;JSON Files (*.json);;HTML Files (*.html)"
        )
        
        if not file_path:
            return
        
        try:
            if selected_filter == "Text Files (*.txt)":
                with open(file_path, 'w', encoding='utf-8') as f:
                    f.write(self.last_results)
            elif selected_filter == "JSON Files (*.json)":
                self.save_as_json(file_path)
            elif selected_filter == "HTML Files (*.html)":
                self.save_as_html(file_path)
            
            QMessageBox.information(self, "Success", f"Report saved successfully to:\n{file_path}")
            self.status_label.setText(f"💾 Report saved to {file_path}")
        except Exception as e:
            QMessageBox.critical(self, "Error", f"Failed to save report:\n{str(e)}")
            self.status_label.setText(f"❌ Failed to save report: {str(e)}")
    
    def save_as_json(self, file_path):
        score, rating, _ = self.calculate_score(self.last_analysis)
        
        report_data = {
            "scan_info": {
                "url": self.last_url,
                "status_code": self.last_status_code,
                "scan_time": datetime.now().isoformat(),
                "scanner_version": "HeaderScanX v3.0"
            },
            "security_score": {
                "score": score,
                "rating": rating,
                "total_headers": len(self.last_analysis) if self.last_analysis else 7,
                "configured_headers": sum(1 for v in self.last_analysis.values() if v['status']) if self.last_analysis else 0
            },
            "headers_analysis": {},
            "virustotal": self.last_vt_results if hasattr(self, 'last_vt_results') else None,
            "recommendations": []
        }
        
        headers_info = {
            'csp': 'Content-Security-Policy',
            'hsts': 'Strict-Transport-Security',
            'xfo': 'X-Frame-Options',
            'xss': 'X-XSS-Protection',
            'xcto': 'X-Content-Type-Options',
            'rp': 'Referrer-Policy',
            'pp': 'Permissions-Policy'
        }
        
        if self.last_analysis:
            for key, display_name in headers_info.items():
                data = self.last_analysis.get(key, {})
                report_data["headers_analysis"][display_name] = {
                    "present": data.get('status', False),
                    "details": data.get('details', ''),
                    "risk": data.get('risk') if data.get('risk') else None
                }
        
        if self.last_analysis:
            if not self.last_analysis.get('csp', {}).get('status', False):
                report_data["recommendations"].append("Implement Content-Security-Policy header to prevent XSS attacks")
            if not self.last_analysis.get('hsts', {}).get('status', False):
                report_data["recommendations"].append("Enable HSTS with max-age=31536000 and includeSubDomains")
            if not self.last_analysis.get('xfo', {}).get('status', False):
                report_data["recommendations"].append("Add X-Frame-Options: DENY to prevent clickjacking")
            if not self.last_analysis.get('xcto', {}).get('status', False):
                report_data["recommendations"].append("Set X-Content-Type-Options: nosniff")
            if not self.last_analysis.get('rp', {}).get('status', False):
                report_data["recommendations"].append("Configure Referrer-Policy: strict-origin-when-cross-origin")
        
        with open(file_path, 'w', encoding='utf-8') as f:
            json.dump(report_data, f, indent=2, ensure_ascii=False)
    
    def save_as_html(self, file_path):
        score, rating, rating_symbol = self.calculate_score(self.last_analysis)
        
        vt_html = ""
        if self.last_vt_results and self.last_vt_results.get('success'):
            vt_status_color = "#7fff7f" if self.last_vt_results['is_safe'] else "#ff6b6b"
            vt_status_text = "SAFE" if self.last_vt_results['is_safe'] else "MALICIOUS"
            vt_html = f"""
        <div class="section">
            <div class="section-title">🔍 VirusTotal Analysis</div>
            <div class="header-item">
                <strong>Status:</strong> <span style="color: {vt_status_color};">{vt_status_text}</span><br>
                <strong>Malicious:</strong> {self.last_vt_results['malicious']}<br>
                <strong>Suspicious:</strong> {self.last_vt_results['suspicious']}<br>
                <strong>Harmless:</strong> {self.last_vt_results['harmless']}<br>
                <strong>Undetected:</strong> {self.last_vt_results['undetected']}<br>
                <strong>Total Scans:</strong> {self.last_vt_results['total_scans']}<br>
                <strong>Reputation:</strong> {self.last_vt_results['reputation']}
            </div>
        </div>"""
        
        html_content = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Security Report - {self.last_url}</title>
    <style>
        * {{ margin: 0; padding: 0; box-sizing: border-box; }}
        body {{
            font-family: 'Courier New', monospace;
            background: linear-gradient(135deg, #0a0e27 0%, #1a1f3a 100%);
            color: #a0f0ff;
            padding: 20px;
            line-height: 1.6;
        }}
        .container {{
            max-width: 1200px;
            margin: 0 auto;
            background: rgba(5, 10, 20, 0.8);
            border-radius: 15px;
            padding: 30px;
            border: 1px solid #2a6f8f;
        }}
        h1 {{ color: #4af0ff; text-align: center; margin-bottom: 30px; }}
        .section {{
            margin-bottom: 30px;
            padding: 20px;
            background: rgba(10, 20, 40, 0.5);
            border-radius: 10px;
            border-left: 3px solid #4af0ff;
        }}
        .section-title {{ color: #4af0ff; font-size: 20px; margin-bottom: 15px; }}
        .header-item {{
            margin-bottom: 15px;
            padding: 10px;
            background: rgba(0, 0, 0, 0.3);
            border-radius: 5px;
        }}
        .status-configured {{ color: #7fff7f; }}
        .status-missing {{ color: #ff6b6b; }}
        .score {{ font-size: 48px; font-weight: bold; text-align: center; margin: 20px 0; }}
        .rating {{ text-align: center; font-size: 24px; margin-bottom: 20px; }}
        .recommendation {{
            padding: 10px;
            margin: 10px 0;
            background: rgba(255, 100, 100, 0.1);
            border-left: 3px solid #ff6b6b;
        }}
        .footer {{ text-align: center; margin-top: 30px; padding-top: 20px; border-top: 1px solid #2a6f8f; }}
        .badge {{
            display: inline-block;
            padding: 3px 8px;
            border-radius: 5px;
            font-size: 11px;
            margin-left: 10px;
        }}
        .badge-success {{ background: rgba(127, 255, 127, 0.2); color: #7fff7f; }}
        .badge-danger {{ background: rgba(255, 107, 107, 0.2); color: #ff6b6b; }}
    </style>
</head>
<body>
    <div class="container">
        <h1>🔒 HeaderScanX Security Report</h1>
        
        <div class="section">
            <div class="section-title">🎯 Target Information</div>
            <div class="header-item">
                <strong>URL:</strong> {self.last_url}<br>
                <strong>Status Code:</strong> {self.last_status_code}<br>
                <strong>Scan Time:</strong> {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
            </div>
        </div>
        
        <div class="section">
            <div class="section-title">📊 Security Score</div>
            <div class="score">{score}/100</div>
            <div class="rating">{rating_symbol} {rating}</div>
        </div>
        
        <div class="section">
            <div class="section-title">🛡️ Security Headers Analysis</div>"""
        
        headers_info = [
            ('Content-Security-Policy', 'csp', '🛡️'),
            ('Strict-Transport-Security', 'hsts', '🔒'),
            ('X-Frame-Options', 'xfo', '🖼️'),
            ('X-XSS-Protection', 'xss', '⚡'),
            ('X-Content-Type-Options', 'xcto', '📄'),
            ('Referrer-Policy', 'rp', '🔗'),
            ('Permissions-Policy', 'pp', '🎯')
        ]
        
        if self.last_analysis:
            for display_name, key, icon in headers_info:
                data = self.last_analysis.get(key, {})
                status_class = "status-configured" if data.get('status', False) else "status-missing"
                status_text = "CONFIGURED" if data.get('status', False) else "MISSING"
                badge_class = "badge-success" if data.get('status', False) else "badge-danger"
                
                html_content += f"""
            <div class="header-item">
                <strong>{icon} {display_name}</strong> <span class="badge {badge_class}">{status_text}</span><br>
                <span class="{status_class}">Analysis:</span> {data.get('details', 'Нет данных')}<br>"""
                
                if data.get('risk'):
                    html_content += f"""<span>Risk:</span> {data['risk']}<br>"""
                
                html_content += """</div>"""
        
        html_content += vt_html + """
        </div>
        
        <div class="section">
            <div class="section-title">💡 Recommendations</div>"""
        
        recommendations_added = False
        if self.last_analysis:
            if not self.last_analysis.get('csp', {}).get('status', False):
                html_content += '<div class="recommendation">• Implement Content-Security-Policy header</div>'
                recommendations_added = True
            if not self.last_analysis.get('hsts', {}).get('status', False):
                html_content += '<div class="recommendation">• Enable HSTS with max-age=31536000</div>'
                recommendations_added = True
            if not self.last_analysis.get('xfo', {}).get('status', False):
                html_content += '<div class="recommendation">• Add X-Frame-Options: DENY</div>'
                recommendations_added = True
            if not self.last_analysis.get('xcto', {}).get('status', False):
                html_content += '<div class="recommendation">• Set X-Content-Type-Options: nosniff</div>'
                recommendations_added = True
            if not self.last_analysis.get('rp', {}).get('status', False):
                html_content += '<div class="recommendation">• Configure Referrer-Policy</div>'
                recommendations_added = True
        
        if not recommendations_added:
            html_content += '<div class="recommendation" style="background: rgba(127, 255, 127, 0.1); border-left-color: #7fff7f;">✓ All headers configured!</div>'
        
        html_content += """
        </div>
        
        <div class="footer">
            <p>Generated by HeaderScanX v3.0</p>
        </div>
    </div>
</body>
</html>"""
        
        with open(file_path, 'w', encoding='utf-8') as f:
            f.write(html_content)
    
    def append_to_output(self, text):
        self.output_text.append(text)
        cursor = self.output_text.textCursor()
        cursor.movePosition(QTextCursor.End)
        self.output_text.setTextCursor(cursor)
    
    def clear_output(self):
        self.output_text.clear()
        self.append_welcome()
        self.status_label.setText("🗑️ Output cleared • Ready for new scan")
        self.save_btn.setEnabled(False)
        self.last_results = None
    
    def start_scan(self):
        url = self.url_input.text().strip()
        if not url:
            self.status_label.setText("⚠️ Please enter a target URL")
            return
        
        if not url.startswith(('http://', 'https://')):
            url = 'https://' + url
            self.url_input.setText(url)
        
        vt_enabled = self.vt_checkbox.isChecked()
        
        self.output_text.clear()
        self.append_to_output(f"\n🔄 Initializing security scan for: {url}\n{'─'*70}\n")
        if vt_enabled:
            self.append_to_output("🔍 VirusTotal reputation check ENABLED\n")
        self.status_label.setText(f"🔍 Scanning {url}...")
        self.scan_btn.setEnabled(False)
        self.save_btn.setEnabled(False)
        self.progress.setVisible(True)
        self.progress.setValue(0)
        
        self.scanner_thread = ScannerThread(url, vt_enabled)
        self.scanner_thread.update_signal.connect(self.update_output)
        self.scanner_thread.vt_signal.connect(self.update_vt_results)
        self.scanner_thread.progress_signal.connect(self.update_progress)
        self.scanner_thread.error_signal.connect(self.show_error)
        self.scanner_thread.finished_signal.connect(self.scan_finished)
        self.scanner_thread.start()
    
    def update_output(self, url, analysis, status_code):
        self.last_url = url
        self.last_analysis = analysis
        self.last_status_code = status_code
        self.update_complete_report()
    
    def update_vt_results(self, vt_results):
        self.last_vt_results = vt_results
        self.update_complete_report()
    
    def update_complete_report(self):
        if self.last_analysis is not None:
            self.last_results = self.format_results(
                self.last_url, 
                self.last_analysis, 
                self.last_status_code, 
                self.last_vt_results
            )
            self.append_to_output(self.last_results)
            self.save_btn.setEnabled(True)
    
    def update_progress(self, value):
        self.progress.setValue(value)
        if value == 100:
            self.status_label.setText("✅ Scan completed! Results ready - You can now save the report")
    
    def show_error(self, error_msg):
        error_text = f"""
{'═'*95}
⚠️ SCAN ERROR
{'═'*95}

Error: {error_msg}

Possible solutions:
• Check if the URL is reachable
• Verify SSL certificate (try http:// instead of https://)
• Ensure the website is online
• Check your internet connection

{'═'*95}
"""
        self.append_to_output(error_text)
        self.status_label.setText(f"❌ Scan failed: {error_msg}")
        self.save_btn.setEnabled(False)
    
    def scan_finished(self):
        self.scan_btn.setEnabled(True)
        self.progress.setVisible(False)
        if self.progress.value() != 100:
            self.status_label.setText("⚠️ Scan interrupted • Ready for retry")
            self.save_btn.setEnabled(False)

def main():
    app = QApplication(sys.argv)
    app.setStyle('Fusion')
    
    window = HeaderScanX()
    window.show()
    sys.exit(app.exec_())

if __name__ == "__main__":
    main()
