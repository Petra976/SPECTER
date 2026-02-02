import sys
import os
import importlib
import pkgutil
from concurrent.futures import ThreadPoolExecutor, as_completed 
from PySide6.QtWidgets import (
    QApplication, QWidget, QVBoxLayout, QPushButton, QLineEdit,
    QTextEdit, QProgressBar, QListWidget, QListWidgetItem,
    QFileDialog, QTabWidget, QTreeWidget, QTreeWidgetItem, QLabel, 
    QHBoxLayout, QFrame, QStyle, QSplitter, QHeaderView
)
from PySide6.QtCore import Qt, QThread, Signal
from PySide6.QtGui import QIcon, QFont, QColor
from PySide6.QtCharts import QChart, QChartView, QBarSeries, QBarSet, QBarCategoryAxis

try:
    from utils.pdf_reporter import generate_pdf_report
    from utils.html_reporter import generate_html_report
    from core.scanner import Scanner
except ImportError:
    # Mocks para testar a GUI sem os arquivos de backend
    print("Modo de Teste de UI: Backend não encontrado.")
    generate_pdf_report = lambda *a: print("PDF Gerado")
    generate_html_report = lambda *a: print("HTML Gerado")
    class Scanner:
        def __init__(self, t): pass
        def run_module(self, m): return {"title": "XSS Test", "severity": "high", "module": "xss_mod"}

# Configuração de Ícone (Caminho)
icon_path = os.path.join(os.getcwd(), '')

def load_modules():
    modules = []
    
    # 1. Obtém o caminho absoluto onde ESTE script está salvo
    # Isso resolve o problema de rodar o script de pastas diferentes
    base_dir = os.path.dirname(os.path.abspath(__file__))
    modules_path = os.path.join(base_dir, "modules")

    # 2. Adiciona o diretório base ao Path do Python para garantir que o import funcione
    if base_dir not in sys.path:
        sys.path.insert(0, base_dir)

    print(f"[*] Buscando módulos em: {modules_path}") # Debug no console

    # 3. Verifica se a pasta existe
    if not os.path.exists(modules_path):
        print(f"[!] Erro Crítico: A pasta 'modules' não foi encontrada em: {modules_path}")
        return []

    # 4. Itera sobre os módulos encontrados
    for _, name, _ in pkgutil.iter_modules([modules_path]):
        try:
            # Importa o módulo (ex: modules.sql_injection)
            mod = importlib.import_module(f"modules.{name}")
            
            # Varre o arquivo em busca de Classes que tenham o método 'run'
            for attr in dir(mod):
                obj = getattr(mod, attr)
                
                # Critério: É uma classe? Tem método run? O módulo é local?
                if isinstance(obj, type) and hasattr(obj, "run"):
                    # Esta verificação extra impede carregar classes importadas de libs externas
                    if obj.__module__ == f"modules.{name}":
                        modules.append(obj)
                        print(f"  [+] Módulo Carregado: {obj.__name__}")
                        
        except Exception as e:
            print(f"  [!] Erro ao importar {name}: {str(e)}")

    if not modules:
        print("[!] Aviso: Nenhum módulo válido (com classe e método .run()) foi encontrado.")
        
    return modules

MODULES = load_modules()

class ScanWorker(QThread):
    log_signal = Signal(str)
    progress_signal = Signal(int)
    result_signal = Signal(list)

    def __init__(self, target, modules):
        super().__init__()
        self.target = target
        self.modules = modules

    def run(self):
        try:
            scanner = Scanner(self.target)
        except:
            scanner = None # Fallback

        results = []
        total = len(self.modules) if self.modules else 1
        done = 0

        # Simulação se não houver backend real
        if not self.modules:
            self.log_signal.emit("[!] Nenhum módulo carregado ou modo de teste.")
            self.progress_signal.emit(100)
            self.result_signal.emit([])
            return

        with ThreadPoolExecutor(max_workers=5) as executor:
            futures = {executor.submit(scanner.run_module, m): m for m in self.modules}
            for future in as_completed(futures):
                module = futures[future]
                try:
                    result = future.result()
                    if result:
                        if isinstance(result, list): results.extend(result)
                        elif isinstance(result, dict): results.append(result)
                        self.log_signal.emit(f"[+] {module.__name__}: Vulnerabilidade detectada")
                    else:
                        self.log_signal.emit(f"[-] {module.__name__}: Limpo")
                except Exception as e:
                    self.log_signal.emit(f"[!] Erro em {module.__name__}: {str(e)}")
                
                done += 1
                self.progress_signal.emit(int((done / total) * 100))

        self.result_signal.emit(results)

class ScannerGUI(QWidget):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("S.P.E.C.T.E.R // Security Auditor")
        self.resize(1200, 800)
        
        self.setStyleSheet(self.get_stylesheet())
        
        self.results = []
        self.current_item = None
        
        if os.path.isfile(icon_path):
            self.setWindowIcon(QIcon(icon_path))
        
        self.init_ui()

    def init_ui(self):
        main_layout = QVBoxLayout(self)
        main_layout.setSpacing(10)
        main_layout.setContentsMargins(15, 15, 15, 15)

        header_layout = QHBoxLayout()
        
        lbl_target = QLabel("TARGET:")
        lbl_target.setObjectName("lblTarget")
        
        self.url_input = QLineEdit()
        self.url_input.setPlaceholderText("https://exemplo.com")
        self.url_input.setClearButtonEnabled(True)

        self.btn_start = QPushButton(" INICIAR SCAN")
        self.btn_start.setObjectName("btnStart")
        self.btn_start.setIcon(self.style().standardIcon(QStyle.SP_MediaPlay))
        self.btn_start.clicked.connect(self.start_scan)

        header_layout.addWidget(lbl_target)
        header_layout.addWidget(self.url_input, 1)
        header_layout.addWidget(self.btn_start)
        
        main_layout.addLayout(header_layout)

        self.progress = QProgressBar()
        self.progress.setTextVisible(False)
        self.progress.setFixedHeight(4)
        main_layout.addWidget(self.progress)

        splitter = QSplitter(Qt.Horizontal)
        
        left_widget = QWidget()
        left_layout = QVBoxLayout(left_widget)
        left_layout.setContentsMargins(0, 0, 5, 0)
        
        lbl_mods = QLabel("MÓDULOS ATIVOS")
        lbl_mods.setObjectName("sectionHeader")
        left_layout.addWidget(lbl_mods)

        self.module_list = QListWidget()
        for m in MODULES:
            item = QListWidgetItem(m.__name__)
            item.setCheckState(Qt.Checked)
            self.module_list.addItem(item)
        left_layout.addWidget(self.module_list)
        
        splitter.addWidget(left_widget)

        center_widget = QWidget()
        center_layout = QVBoxLayout(center_widget)
        center_layout.setContentsMargins(5, 0, 5, 0)

        self.tabs = QTabWidget()
        
        self.log_box = QTextEdit()
        self.log_box.setReadOnly(True)
        self.log_box.setObjectName("logBox")
        self.tabs.addTab(self.log_box, "Console Log")

        self.tree = QTreeWidget()
        self.tree.setHeaderLabels(["Título", "Severidade", "Módulo", "Categoria"])
        self.tree.header().setSectionResizeMode(0, QHeaderView.Stretch)
        self.tree.itemClicked.connect(self.load_finding_details)
        self.tree.setAlternatingRowColors(True)
        self.tabs.addTab(self.tree, "Resultados")

        self.details_box = QTextEdit()
        self.details_box.setReadOnly(True)
        self.tabs.addTab(self.details_box, "Detalhes Técnicos")

        self.chart_view = QChartView()
        self.tabs.addTab(self.chart_view, "Dashboard")

        center_layout.addWidget(self.tabs)
        splitter.addWidget(center_widget)

        right_widget = QWidget()
        right_layout = QVBoxLayout(right_widget)
        right_layout.setContentsMargins(5, 0, 0, 0)

        lbl_notes = QLabel("ANOTAÇÕES")
        lbl_notes.setObjectName("sectionHeader")
        right_layout.addWidget(lbl_notes)

        self.notes_box = QTextEdit()
        self.notes_box.setPlaceholderText("Notas do auditor...")
        right_layout.addWidget(self.notes_box)

        self.btn_save_note = QPushButton("Salvar Nota")
        self.btn_save_note.setIcon(self.style().standardIcon(QStyle.SP_DialogSaveButton))
        self.btn_save_note.clicked.connect(self.save_note)
        right_layout.addWidget(self.btn_save_note)

        # Separator line
        line = QFrame()
        line.setFrameShape(QFrame.HLine)
        line.setFrameShadow(QFrame.Sunken)
        right_layout.addWidget(line)

        lbl_export = QLabel("RELATÓRIOS")
        lbl_export.setObjectName("sectionHeader")
        right_layout.addWidget(lbl_export)

        btn_html = QPushButton("Exportar HTML")
        btn_html.setIcon(self.style().standardIcon(QStyle.SP_DialogHelpButton)) # Placeholder icon
        btn_html.clicked.connect(self.export_html)
        right_layout.addWidget(btn_html)

        btn_pdf = QPushButton("Exportar PDF")
        btn_pdf.setIcon(self.style().standardIcon(QStyle.SP_FileIcon))
        btn_pdf.clicked.connect(self.export_pdf)
        right_layout.addWidget(btn_pdf)

        splitter.addWidget(right_widget)
        
        # Ajustar proporções do splitter (20% esquerda, 60% centro, 20% direita)
        splitter.setSizes([200, 600, 250])

        main_layout.addWidget(splitter)

    # ================= LOGIC =================

    def start_scan(self):
        target = self.url_input.text().strip()
        if not target:
            self.log("Erro: URL inválida.")
            return
            
        self.btn_start.setEnabled(False)
        self.log_box.clear()
        self.tree.clear()
        self.log(f"[*] Iniciando scan em: {target}")
        
        selected_modules = [
            MODULES[i] for i in range(self.module_list.count())
            if self.module_list.item(i).checkState() == Qt.Checked
        ]

        self.worker = ScanWorker(target, selected_modules)
        self.worker.log_signal.connect(self.log)
        self.worker.progress_signal.connect(self.progress.setValue)
        self.worker.result_signal.connect(self.scan_finished)
        self.worker.start()

    def scan_finished(self, results):
        self.btn_start.setEnabled(True)
        self.progress.setValue(100)
        
        # Normalização dos resultados
        fixed = []
        for r in results:
            if not isinstance(r, dict): continue
            r.setdefault("title", "Finding")
            r.setdefault("description", "No description")
            r.setdefault("severity", "info")
            r.setdefault("module", "unknown")
            r.setdefault("category", "General")
            r.setdefault("business_impact", "-")
            r.setdefault("remediation", "-")
            r.setdefault("evidence", "")
            r.setdefault("notes", "")
            fixed.append(r)

        self.results = fixed
        self.populate_tree()
        self.build_chart()
        self.log("\n[✓] Scan concluído com sucesso.")

    def log(self, text):
        self.log_box.append(text)
        # Auto scroll
        sb = self.log_box.verticalScrollBar()
        sb.setValue(sb.maximum())

    # ================= DATA VISUALIZATION =================

    def populate_tree(self):
        self.tree.clear()
        for r in self.results:
            item = QTreeWidgetItem([
                r["title"],
                r["severity"].upper(),
                r["module"],
                r["category"]
            ])
            
            # Colorir baseado na severidade
            sev = r["severity"].lower()
            color = QColor("white")
            if sev == "critical": color = QColor("#ff2e63")
            elif sev == "high": color = QColor("#ff6f61")
            elif sev == "medium": color = QColor("#feb236")
            elif sev == "low": color = QColor("#00bcd4")
            
            item.setForeground(1, color)
            item.setData(0, Qt.UserRole, r)
            self.tree.addTopLevelItem(item)

    def load_finding_details(self, item, column):
        finding = item.data(0, Qt.UserRole)
        self.current_item = item
        self.notes_box.setText(finding.get("notes", ""))

        html = f"""
        <h2 style='color:#00bcd4'>{finding['title']}</h2>
        <table border='0' cellpadding='4'>
            <tr><td><b>Severidade:</b></td><td style='color:orange'>{finding['severity'].upper()}</td></tr>
            <tr><td><b>Módulo:</b></td><td>{finding['module']}</td></tr>
            <tr><td><b>Categoria:</b></td><td>{finding['category']}</td></tr>
        </table>
        <hr>
        <h3>Descrição</h3>
        <p>{finding['description']}</p>
        <h3>Impacto</h3>
        <p>{finding['business_impact']}</p>
        <h3>Evidência</h3>
        <pre style='background-color:#222; padding:5px;'>{finding['evidence']}</pre>
        <h3>Remediação</h3>
        <p style='color:#8fce00'>{finding['remediation']}</p>
        """
        self.details_box.setHtml(html)

    def save_note(self):
        if self.current_item:
            finding = self.current_item.data(0, Qt.UserRole)
            finding["notes"] = self.notes_box.toPlainText()
            self.log("[*] Nota salva localmente.")

    def build_chart(self):
        counts = {"info": 0, "low": 0, "medium": 0, "high": 0, "critical": 0}
        for r in self.results:
            sev = r["severity"].lower()
            if sev in counts: counts[sev] += 1

        set0 = QBarSet("Ocorrências")
        set0.append([counts[k] for k in counts])
        set0.setColor(QColor("#00bcd4"))

        series = QBarSeries()
        series.append(set0)

        chart = QChart()
        chart.addSeries(series)
        chart.setTitle("Distribuição de Vulnerabilidades")
        chart.setAnimationOptions(QChart.SeriesAnimations)
        chart.setBackgroundBrush(Qt.NoBrush) # Fundo transparente para herdar tema
        chart.setTitleBrush(QColor("white"))
        chart.legend().setLabelColor(QColor("white"))
        
        # Eixo X
        axisX = QBarCategoryAxis()
        axisX.append([k.upper() for k in counts.keys()])
        axisX.setLabelsColor(QColor("white"))
        chart.addAxis(axisX, Qt.AlignBottom)
        series.attachAxis(axisX)

        self.chart_view.setChart(chart)

    # ================= EXPORTS =================

    def export_pdf(self):
        if not self.results: return
        path, _ = QFileDialog.getSaveFileName(self, "Salvar PDF", "", "PDF (*.pdf)")
        if path: generate_pdf_report(self.results, path, self.url_input.text())

    def export_html(self):
        if not self.results: return
        path, _ = QFileDialog.getSaveFileName(self, "Salvar HTML", "", "HTML (*.html)")
        if path: generate_html_report(self.results, path, self.url_input.text(), "wpf_icon.ico")

    # ================= STYLESHEET =================

    def get_stylesheet(self):
        return """
        QWidget {
            background-color: #1e1e2e;
            color: #cdd6f4;
            font-family: 'Segoe UI', 'Roboto', sans-serif;
            font-size: 14px;
        }
        
        /* --- BUTTONS --- */
        QPushButton {
            background-color: #313244;
            border: 1px solid #45475a;
            border-radius: 6px;
            padding: 8px 16px;
            color: #fff;
            font-weight: bold;
        }
        QPushButton:hover {
            background-color: #45475a;
            border-color: #585b70;
        }
        QPushButton:pressed {
            background-color: #00bcd4;
            color: #1e1e2e;
        }
        QPushButton#btnStart {
            background-color: #00bcd4;
            color: #1e1e2e;
            font-size: 15px;
            border: none;
        }
        QPushButton#btnStart:hover {
            background-color: #00acc1;
        }

        /* --- INPUTS --- */
        QLineEdit {
            background-color: #181825;
            border: 1px solid #313244;
            border-radius: 6px;
            padding: 8px;
            color: #00bcd4;
            font-size: 14px;
        }
        QLineEdit:focus {
            border: 1px solid #00bcd4;
        }
        QTextEdit {
            background-color: #181825;
            border: 1px solid #313244;
            border-radius: 6px;
            font-family: 'Consolas', 'Monospace';
        }

        /* --- LISTS & TREES --- */
        QListWidget, QTreeWidget {
            background-color: #181825;
            border: 1px solid #313244;
            border-radius: 6px;
            outline: none;
        }
        QListWidget::item, QTreeWidget::item {
            padding: 8px;
        }
        QListWidget::item:selected, QTreeWidget::item:selected {
            background-color: #313244;
            color: #00bcd4;
            border-left: 3px solid #00bcd4;
        }
        QHeaderView::section {
            background-color: #1e1e2e;
            color: #a6adc8;
            padding: 5px;
            border: none;
            border-bottom: 2px solid #313244;
            font-weight: bold;
        }

        /* --- TABS --- */
        QTabWidget::pane {
            border: 1px solid #313244;
            border-radius: 6px;
            background: #1e1e2e;
        }
        QTabBar::tab {
            background: #1e1e2e;
            color: #a6adc8;
            padding: 10px 20px;
            margin-right: 2px;
            border-top-left-radius: 6px;
            border-top-right-radius: 6px;
        }
        QTabBar::tab:selected {
            background: #313244;
            color: #00bcd4;
            border-bottom: 2px solid #00bcd4;
        }

        /* --- OTHERS --- */
        QLabel#lblTarget {
            color: #00bcd4;
            font-weight: bold;
            font-size: 16px;
            margin-right: 10px;
        }
        QLabel#sectionHeader {
            color: #a6adc8;
            font-size: 12px;
            font-weight: bold;
            text-transform: uppercase;
            margin-bottom: 5px;
            margin-top: 10px;
        }
        QProgressBar {
            background-color: #313244;
            border-radius: 2px;
        }
        QProgressBar::chunk {
            background-color: #00bcd4;
        }
        QSplitter::handle {
            background-color: #313244;
        }
        """

if __name__ == "__main__":
    app = QApplication(sys.argv)
    font = QFont("Segoe UI", 10)
    app.setFont(font)
    
    window = ScannerGUI()
    window.show()
    sys.exit(app.exec())