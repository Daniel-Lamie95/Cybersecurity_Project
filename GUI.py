import sys
import os
import bcrypt
from PyQt5.QtWidgets import (QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout, 
    QPushButton, QLabel, QLineEdit, QDialog, QMessageBox, 
    QFileDialog, QComboBox, QSpinBox, QTextEdit, QFrame)
from PyQt5.QtCore import QThread, pyqtSignal, Qt
from project import AES, RSA 

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

    QComboBox { 
        background-color: #45475a; 
        border-radius: 8px; 
        padding: 8px; 
        color: white;
    }
    
    QTextEdit { 
        background-color: #181825; 
        border-radius: 12px; 
        color: #a6e3a1; 
        font-family: 'Consolas', monospace; 
        font-size: 13px;
    }
"""

class WorkerThread(QThread):
    finished = pyqtSignal(bool, str)
    def __init__(self, func, *args):
        super().__init__()
        self.func = func
        self.args = args
    def run(self):
        try:
            self.func(*self.args)
            self.finished.emit(True, "Task Completed Successfully")
        except Exception as e:
            self.finished.emit(False, str(e))

class RegisterDialog(QDialog):
    def __init__(self):
        super().__init__()
        self.setStyleSheet(MODERN_STYLE)
        self.setWindowTitle("SecureNet  - Create Account")
        self.setFixedSize(600, 750)
        self.init_ui()

    def init_ui(self):
        layout = QVBoxLayout(self)
        layout.setContentsMargins(50, 50, 50, 50)
        layout.setSpacing(20)
        title = QLabel("Registration")
        title.setObjectName("Header")
        title.setAlignment(Qt.AlignCenter)
        layout.addWidget(title)

        self.username = QLineEdit(placeholderText="Name")
        layout.addWidget(QLabel("User Name:"))
        layout.addWidget(self.username)

        self.password = QLineEdit(placeholderText="Password")
        self.password.setEchoMode(QLineEdit.Password)
        self.password.textChanged.connect(self.check_input)
        layout.addWidget(QLabel("User Password:"))
        layout.addWidget(self.password)

        msg_card = QFrame(); msg_card.setObjectName("Card")
        msg_layout = QVBoxLayout(msg_card)
        self.lbl_len = QLabel("- 8+ characters"); self.lbl_upper = QLabel("- Uppercase")
        self.lbl_lower = QLabel("- Lowercase"); self.lbl_num = QLabel("- Number")
        self.lbl_spec = QLabel("- Special Char")
        self.labels = [self.lbl_len, self.lbl_upper, self.lbl_lower, self.lbl_num, self.lbl_spec]
        for lbl in self.labels:
            lbl.setStyleSheet("color: #f38ba8; font-size: 13px;")
            msg_layout.addWidget(lbl)
        layout.addWidget(msg_card)

        self.reg_btn = QPushButton("CREATE ACCOUNT")
        self.reg_btn.setEnabled(False)
        self.reg_btn.clicked.connect(self.handle_register)
        layout.addWidget(self.reg_btn)

    def check_input(self):
        pwd = self.password.text()
        spec = "!@#$%^&*()_+-=[]{}|;:,.<>?/~`"
        checks = [len(pwd) >= 8, any(x.isupper() for x in pwd), any(x.islower() for x in pwd), any(x.isdigit() for x in pwd), any(x in spec for x in pwd)]
        for i, met in enumerate(checks):
            color = "#a6e3a1" if met else "#f38ba8"
            self.labels[i].setStyleSheet(f"color: {color}; font-size: 13px;")
        self.reg_btn.setEnabled(all(checks))

    def handle_register(self):
        user = self.username.text().strip()
        pwd = self.password.text()
        if os.path.exists("users.txt"):
            with open("users.txt", "r") as f:
                if any(line.split("|")[0].lower() == user.lower() for line in f):
                    QMessageBox.warning(self, "Error", "Username already taken.")
                    return
        hashed = bcrypt.hashpw(pwd.encode(), bcrypt.gensalt())
        with open("users.txt", "a") as f: f.write(f"{user}|{hashed.decode()}\n")
        QMessageBox.information(self, "Success", "Account created! You can now login.")
        self.accept()

class LoginDialog(QDialog):
    signup_requested = pyqtSignal()

    def __init__(self):
        super().__init__()
        self.auth_user = None
        self.setStyleSheet(MODERN_STYLE)
        self.setWindowTitle("SecureNet  - Login")
        self.setFixedSize(500, 550)
        self.init_ui()

    def init_ui(self):
        layout = QVBoxLayout(self)
        layout.setContentsMargins(50, 50, 50, 50)
        layout.setSpacing(20)
        title = QLabel("Welcome Back")
        title.setObjectName("Header")
        title.setAlignment(Qt.AlignCenter)
        layout.addWidget(title)

        self.username = QLineEdit(placeholderText="Username")
        layout.addWidget(self.username)
        self.password = QLineEdit(placeholderText="Password")
        self.password.setEchoMode(QLineEdit.Password)
        layout.addWidget(self.password)

        self.login_btn = QPushButton("LOGIN")
        self.login_btn.setObjectName("ActionBtn")
        self.login_btn.clicked.connect(self.handle_login)
        layout.addWidget(self.login_btn)

        self.signup_btn = QPushButton("Don't have an account? Register here")
        self.signup_btn.setStyleSheet("background:transparent; color:#89b4fa; text-decoration:underline; border:none;")
        self.signup_btn.clicked.connect(self.handle_signup_click)
        layout.addWidget(self.signup_btn)

    def handle_signup_click(self):
        self.signup_requested.emit()
        self.reject()

    def handle_login(self):
        user_in, pwd_in = self.username.text().strip(), self.password.text().strip()
        if not os.path.exists("users.txt"):
            QMessageBox.warning(self, "Error", "No users found. Please register.")
            return
        with open("users.txt", "r") as f:
            for line in f:
                u, h = line.strip().split("|")
                if u == user_in and bcrypt.checkpw(pwd_in.encode(), h.encode()):
                    self.auth_user = u
                    self.accept()
                    return
        QMessageBox.warning(self, "Denied", "Invalid username or password.")

class EncryptionWindow(QMainWindow):
    def __init__(self, username):
        super().__init__()
        self.username = username
        self.aes_tool = None
        self.rsa_tool = RSA()
        self.setStyleSheet(MODERN_STYLE)
        self.init_ui()

    def init_ui(self):
        self.setWindowTitle(f"SecureNet  Pro - {self.username}")
        self.resize(1000, 850)
        central = QWidget(); self.setCentralWidget(central)
        main_layout = QVBoxLayout(central); main_layout.setContentsMargins(40, 40, 40, 40)
        
        header = QLabel(f"Encryption Window: "); header.setObjectName("Header")
        main_layout.addWidget(header)

        settings_card = QFrame(); settings_card.setObjectName("Card")
        settings_layout = QVBoxLayout(settings_card)
        self.mechanism = QComboBox()
        self.mechanism.addItems(["AES-128", "AES-192", "AES-256", "RSA Asymmetric"])
        self.mechanism.currentTextChanged.connect(self.toggle_mode)
        settings_layout.addWidget(QLabel("Security Protocol:")); settings_layout.addWidget(self.mechanism)

        self.aes_group = QWidget(); aes_lay = QHBoxLayout(self.aes_group)
        self.aes_pass = QLineEdit(placeholderText="AES Password"); self.aes_pass.setEchoMode(QLineEdit.Password)
        self.init_aes_btn = QPushButton("Set Key"); self.init_aes_btn.clicked.connect(self.init_aes)
        aes_lay.addWidget(self.aes_pass, 3); aes_lay.addWidget(self.init_aes_btn, 1)
        settings_layout.addWidget(self.aes_group)

        self.rsa_group = QWidget(); rsa_lay = QHBoxLayout(self.rsa_group)
        self.rsa_gen_btn = QPushButton("Generate RSA Keys"); self.rsa_gen_btn.clicked.connect(self.init_rsa)
        rsa_lay.addWidget(self.rsa_gen_btn); self.rsa_group.hide(); settings_layout.addWidget(self.rsa_group)
        main_layout.addWidget(settings_card)

        file_card = QFrame(); file_card.setObjectName("Card"); file_layout = QHBoxLayout(file_card)
        self.file_info = QLabel("Target: No file selected")
        btn_browse = QPushButton("Browse"); btn_browse.clicked.connect(self.get_file)
        file_layout.addWidget(self.file_info, 4); file_layout.addWidget(btn_browse, 1)
        main_layout.addWidget(file_card)

        btn_box = QHBoxLayout()
        self.btn_enc = QPushButton("ENCRYPT"); self.btn_enc.setObjectName("ActionBtn")
        self.btn_dec = QPushButton("DECRYPT"); self.btn_dec.setObjectName("SecondaryBtn")
        self.btn_enc.clicked.connect(lambda: self.process(True)); self.btn_dec.clicked.connect(lambda: self.process(False))
        btn_box.addWidget(self.btn_enc); btn_box.addWidget(self.btn_dec); main_layout.addLayout(btn_box)

        self.log_box = QTextEdit(); self.log_box.setReadOnly(True); main_layout.addWidget(self.log_box)

    def toggle_mode(self, text):
        is_aes = "AES" in text
        self.aes_group.setVisible(is_aes); self.rsa_group.setVisible(not is_aes)

    def init_aes(self):
        bits = int(self.mechanism.currentText().split("-")[1])
        self.aes_tool = AES(self.aes_pass.text(), bits)
        self.log_box.append(f"SYSTEM: AES-{bits} engine ready.")

    def init_rsa(self):
        self.rsa_tool.generate_Keys(); self.rsa_tool.save_Keys()
        self.log_box.append("SYSTEM: RSA Keypair saved.")

    def get_file(self):
        p, _ = QFileDialog.getOpenFileName(self, "Open File")
        if p: self.file_path = p; self.file_info.setText(f"Target: {os.path.basename(p)}")

    def process(self, encrypt=True):
        if not hasattr(self, 'file_path'): return
        out = self.file_path + (".enc" if encrypt else "_decrypted.txt")
        tool = self.aes_tool if "AES" in self.mechanism.currentText() else self.rsa_tool
        func = tool.encrypt_file if encrypt else tool.decrypt_file
        self.worker = WorkerThread(func, self.file_path, out)
        self.worker.finished.connect(lambda s, m: self.log_box.append(f"STATUS: {m}"))
        self.worker.start()


if __name__ == "__main__":
    app = QApplication(sys.argv)
    verified_user = None
    
    while verified_user is None:
        login_dlg = LoginDialog()
        register_requested = [False] # Use a list to make it mutable inside the nested function
        
        def on_signup(): register_requested[0] = True
        login_dlg.signup_requested.connect(on_signup)
        
        result = login_dlg.exec_()
        
        if result == QDialog.Accepted:
            verified_user = login_dlg.auth_user
        elif register_requested[0]:
            reg_dlg = RegisterDialog()
            reg_dlg.exec_()
            # Loop continues, showing login page again
        else:
            sys.exit() # User clicked X or Cancel

    main_win = EncryptionWindow(verified_user)
    main_win.show()
    sys.exit(app.exec_())
