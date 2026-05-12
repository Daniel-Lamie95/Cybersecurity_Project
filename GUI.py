import sys
import os
import bcrypt
from PyQt5.QtWidgets import (QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout, 
   QPushButton, QLabel, QLineEdit, QDialog, QMessageBox, 
         QFileDialog, QComboBox, QSpinBox, QTextEdit, QFrame)
from PyQt5.QtCore import QThread, pyqtSignal, Qt
from project import AES, RSA 

# --- MODERN DARK STYLESHEET ---
MODERN_STYLE = """
    QMainWindow, QDialog { background-color: #1e1e2e; }
    QWidget { background-color: #1e1e2e; color: #cdd6f4; font-family: 'Segoe UI', sans-serif; }
    
    QFrame#Card { 
        background-color: #313244; 
        border-radius: 15px; 
        padding: 25px; 
        margin: 5px;
    }
    
    QLabel { font-size: 15px; }
    QLabel#Header { font-size: 32px; font-weight: bold; color: #89b4fa; margin-bottom: 10px; }
    
    QLineEdit { 
        background-color: #45475a; 
        border: 2px solid #585b70; 
        border-radius: 10px; 
        padding: 12px; 
        color: white; 
        font-size: 14px;
    }
    QLineEdit:focus { border: 2px solid #89b4fa; }

    QPushButton { 
        background-color: #89b4fa; 
        color: #1e1e2e; 
        font-weight: bold; 
        border-radius: 10px; 
        padding: 15px; 
        font-size: 14px;
    }
    QPushButton:hover { background-color: #b4befe; }
    QPushButton:disabled { background-color: #585b70; color: #7f849c; }
    
    QPushButton#ActionBtn { background-color: #a6e3a1; color: #11111b; font-size: 16px; }
    QPushButton#SecondaryBtn { background-color: #f9e2af; color: #11111b; font-size: 16px; }

    QComboBox, QSpinBox { 
        background-color: #45475a; 
        border-radius: 8px; 
        padding: 8px; 
        color: white;
        font-size: 14px;
    }
    
    QTextEdit { 
        background-color: #181825; 
        border-radius: 12px; 
        color: #a6e3a1; 
        font-family: 'Consolas', monospace; 
        font-size: 13px;
        padding: 10px;
    }
"""

class WorkerThread(QThread):
    finished = pyqtSignal(bool, str)
    error = pyqtSignal(str)

    def __init__(self, func, *args):
        super().__init__()
        self.func = func
        self.args = args

    def run(self):
        try:
            self.func(*self.args)
            self.finished.emit(True, "Task Completed Successfully")
        except Exception as e:
            self.error.emit(str(e))

class RegisterDialog(QDialog):
    def __init__(self):
        super().__init__()
        self.username_text = ""
        self.setStyleSheet(MODERN_STYLE)
        self.setWindowTitle("ShieldCrypt - Account Creation")
        self.setFixedSize(550, 650) # Larger Registration Dialog
        self.init_ui()

    def init_ui(self):
        layout = QVBoxLayout(self)
        layout.setContentsMargins(50, 50, 50, 50)
        layout.setSpacing(15)

        title = QLabel("Create Account")
        title.setObjectName("Header")
        title.setAlignment(Qt.AlignCenter)
        layout.addWidget(title)

        self.username = QLineEdit(placeholderText="Username")
        layout.addWidget(QLabel("Choose Username:"))
        layout.addWidget(self.username)

        self.password = QLineEdit(placeholderText="Strong Password")
        self.password.setEchoMode(QLineEdit.Password)
        self.password.textChanged.connect(self.check_input)
        layout.addWidget(QLabel("Choose Password:"))
        layout.addWidget(self.password)

        # Validation Labels
        self.lbl_len = QLabel("- Length: Minimum 8 characters")
        self.lbl_upper = QLabel("- Requirement: One uppercase letter")
        self.lbl_lower = QLabel("- Requirement: One lowercase letter")
        self.lbl_num = QLabel("- Requirement: One numeric digit")
        self.lbl_spec = QLabel("- Requirement: One special character")
        
        for lbl in [self.lbl_len, self.lbl_upper, self.lbl_lower, self.lbl_num, self.lbl_spec]:
            lbl.setStyleSheet("color: #f38ba8; font-size: 12px;")
            layout.addWidget(lbl)

        layout.addStretch()

        self.reg_btn = QPushButton("CREATE ACCOUNT")
        self.reg_btn.setEnabled(False)
        self.reg_btn.clicked.connect(self.handle_register)
        layout.addWidget(self.reg_btn)

    def check_input(self):
        pwd = self.password.text()
        special_chars = "!@#$%^&*()_+-=[]{}|;:,.<>?/~`"

        c1 = len(pwd) >= 8
        c2 = any(c.isupper() for c in pwd)
        c3 = any(c.islower() for c in pwd)
        c4 = any(c.isdigit() for c in pwd)
        c5 = any(c in special_chars for c in pwd)

        self.update_lbl(self.lbl_len, c1)
        self.update_lbl(self.lbl_upper, c2)
        self.update_lbl(self.lbl_lower, c3)
        self.update_lbl(self.lbl_num, c4)
        self.update_lbl(self.lbl_spec, c5)

        self.reg_btn.setEnabled(all([c1, c2, c3, c4, c5]))

    def update_lbl(self, label, condition):
        if condition:
            label.setStyleSheet("color: #a6e3a1; font-size: 12px; font-weight: bold;")
        else:
            label.setStyleSheet("color: #f38ba8; font-size: 12px;")

    def handle_register(self):
        user = self.username.text().strip()
        pwd = self.password.text()
        if len(user) < 3:
            QMessageBox.warning(self, "Error", "Username is too short.")
            return
        
        try:
            hashed = bcrypt.hashpw(pwd.encode(), bcrypt.gensalt())
            with open("users.txt", "a") as f:
                f.write(f"{user}|{hashed.decode()}\n")
            self.username_text = user
            self.accept()
        except Exception as e:
            QMessageBox.critical(self, "System Error", f"Could not save user: {e}")

class EncryptionWindow(QMainWindow):
    def __init__(self, username):
        super().__init__()
        self.username = username
        self.aes_tool = None
        self.rsa_tool = RSA()
        self.setStyleSheet(MODERN_STYLE)
        self.init_ui()

    def init_ui(self):
        self.setWindowTitle(f"ShieldCrypt Pro - {self.username}")
        self.resize(1000, 850) # Significantly larger main window
        
        central = QWidget()
        self.setCentralWidget(central)
        main_layout = QVBoxLayout(central)
        main_layout.setContentsMargins(40, 40, 40, 40)
        main_layout.setSpacing(25)

        header = QLabel(f"Vault Operator: {self.username}")
        header.setObjectName("Header")
        main_layout.addWidget(header)

        # Settings Card
        settings_card = QFrame()
        settings_card.setObjectName("Card")
        settings_layout = QVBoxLayout(settings_card)
        
        row1 = QHBoxLayout()
        row1.addWidget(QLabel("Encryption Method:"))
        self.mechanism = QComboBox()
        self.mechanism.addItems(["AES-Symmetric (Files)", "RSA-Asymmetric (Keys/Small Data)"])
        self.mechanism.currentTextChanged.connect(self.toggle_mode)
        row1.addWidget(self.mechanism, 1)
        settings_layout.addLayout(row1)

        self.aes_group = QWidget()
        aes_lay = QHBoxLayout(self.aes_group)
        self.aes_pass = QLineEdit(placeholderText="Session Password")
        self.aes_pass.setEchoMode(QLineEdit.Password)
        self.key_size = QSpinBox()
        self.key_size.setRange(128, 256)
        self.key_size.setValue(256)
        self.init_aes_btn = QPushButton("Set AES Key")
        self.init_aes_btn.clicked.connect(self.init_aes)
        aes_lay.addWidget(self.aes_pass, 3)
        aes_lay.addWidget(self.key_size, 1)
        aes_lay.addWidget(self.init_aes_btn, 1)
        settings_layout.addWidget(self.aes_group)

        self.rsa_group = QWidget()
        rsa_lay = QHBoxLayout(self.rsa_group)
        self.rsa_gen_btn = QPushButton("Generate and Save RSA Keys")
        self.rsa_gen_btn.clicked.connect(self.init_rsa)
        rsa_lay.addWidget(self.rsa_gen_btn)
        self.rsa_group.hide()
        settings_layout.addWidget(self.rsa_group)

        main_layout.addWidget(settings_card)

        # File Selection Card
        file_card = QFrame()
        file_card.setObjectName("Card")
        file_layout = QHBoxLayout(file_card)
        self.file_info = QLabel("Target: No file selected")
        self.btn_browse = QPushButton("Browse")
        self.btn_browse.setFixedWidth(150)
        self.btn_browse.clicked.connect(self.get_file)
        file_layout.addWidget(self.file_info, 4)
        file_layout.addWidget(self.btn_browse, 1)
        main_layout.addWidget(file_card)

        # Action Buttons
        btn_box = QHBoxLayout()
        self.btn_enc = QPushButton("ENCRYPT FILE")
        self.btn_enc.setObjectName("ActionBtn")
        self.btn_enc.setFixedHeight(60)
        self.btn_enc.clicked.connect(self.run_encrypt)
        
        self.btn_dec = QPushButton("DECRYPT FILE")
        self.btn_dec.setObjectName("SecondaryBtn")
        self.btn_dec.setFixedHeight(60)
        self.btn_dec.clicked.connect(self.run_decrypt)
        
        btn_box.addWidget(self.btn_enc)
        btn_box.addWidget(self.btn_dec)
        main_layout.addLayout(btn_box)

        # Log Box
        self.log_box = QTextEdit()
        self.log_box.setReadOnly(True)
        self.log_box.setPlaceholderText("System activity will be logged here...")
        main_layout.addWidget(self.log_box)

    def toggle_mode(self, text):
        is_aes = "AES" in text
        self.aes_group.setVisible(is_aes)
        self.rsa_group.setVisible(not is_aes)

    def init_aes(self):
        if len(self.aes_pass.text()) < 1: return
        self.aes_tool = AES(self.aes_pass.text(), self.key_size.value())
        self.log_box.append("SYSTEM: AES Engine Active")

    def init_rsa(self):
        self.rsa_tool.generate_Keys()
        self.rsa_tool.save_Keys()
        self.log_box.append("SYSTEM: RSA Keypair generated and saved to folder")

    def get_file(self):
        p, _ = QFileDialog.getOpenFileName(self, "Open Data File")
        if p:
            self.file_path = p
            self.file_info.setText(f"Target: {os.path.basename(p)}")

    def run_encrypt(self):
        if not hasattr(self, 'file_path'): return
        out = self.file_path + ".enc"
        tool = self.aes_tool if self.aes_group.isVisible() else self.rsa_tool
        self.worker = WorkerThread(tool.encrypt_file, self.file_path, out)
        self.worker.finished.connect(lambda s, m: self.log_box.append(f"SUCCESS: {m}"))
        self.worker.start()

    def run_decrypt(self):
        if not hasattr(self, 'file_path'): return
        out = self.file_path.replace(".enc", "_decrypted.txt")
        tool = self.aes_tool if self.aes_group.isVisible() else self.rsa_tool
        self.worker = WorkerThread(tool.decrypt_file, self.file_path, out)
        self.worker.finished.connect(lambda s, m: self.log_box.append(f"SUCCESS: {m}"))
        self.worker.start()

if __name__ == "__main__":
    app = QApplication(sys.argv)
    reg_page = RegisterDialog()
    if reg_page.exec_() == QDialog.Accepted:
        main_win = EncryptionWindow(reg_page.username_text)
        main_win.show()
        sys.exit(app.exec_())
