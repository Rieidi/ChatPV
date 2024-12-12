import customtkinter as ctk
from tkinter import filedialog, messagebox, END
from pymongo import MongoClient, errors
from datetime import datetime, timezone
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from bson.binary import Binary
import base64
import binascii
import os
import shutil
import time
import pytz
import threading
from plyer import notification
import keyring

class ChatApplication(ctk.CTk):
    def __init__(self):
        super().__init__()
        self.senha_incorreta = 0
        self.bloqueado_ate = None
        self.caminho_arquivo_bloqueio = "bloqueio.temp"

        # Verifica se há um bloqueio ativo
        self.verify_and_close_if_locked()
        
        ctk.set_appearance_mode("Dark")
        ctk.set_default_color_theme("green")
        self.geometry("550x550")
        self.title("ChatPv")
        self.protocol("WM_DELETE_WINDOW", self.on_closing)
        self.resizable(False, False)

        # Variáveis principais
        self.client = None
        self.db = None
        self.collection = None
        self.nome_usuario = None
        self.encryption_key = None
        self.mensagens_exibidas = set()
        self.bloquear_notificacoes = False
        self.senha_incorreta = 0
        self.bloqueado_ate = None
        self.temp_dir = os.path.join(os.getcwd(), "temp")
        self.UserMSG = "None"  # Substitua "MeuNome" pelo nome dinâmico configurado pelo usuário


        # Configuração inicial
        self.setup_initial_frame()

    def setup_initial_frame(self):
        """Janela inicial para configuração."""
        self.initial_frame = ctk.CTkFrame(self, fg_color="transparent")
        self.initial_frame.pack(pady=20, padx=20, fill="both", expand=True)

        ctk.CTkLabel(self.initial_frame, text="Configuração Inicial", font=("Arial", 18, "bold")).pack(pady=10)

        self.uri_entry = ctk.CTkEntry(self.initial_frame, placeholder_text="URI do MongoDB (sem senha)", width=450)
        self.uri_entry.pack(pady=5)

        self.database_entry = ctk.CTkEntry(self.initial_frame, placeholder_text="Nome da Base de Dados", width=450)
        self.database_entry.pack(pady=5)

        self.collection_entry = ctk.CTkEntry(self.initial_frame, placeholder_text="Nome da Coleção", width=450)
        self.collection_entry.pack(pady=5)

        self.encryption_key_entry = ctk.CTkEntry(
            self.initial_frame, placeholder_text="Chave de Criptografia (hexadecimal)", width=450, show="*"
        )
        self.encryption_key_entry.pack(pady=5)

        self.username_entry = ctk.CTkEntry(self.initial_frame, placeholder_text="Seu Nome de Usuário", width=450)
        self.username_entry.pack(pady=5)

        self.password_entry = ctk.CTkEntry(self.initial_frame, placeholder_text="Senha do MongoDB", width=450, show="*")
        self.password_entry.pack(pady=5)

        ctk.CTkButton(self.initial_frame, text="Confirmar", command=self.confirm_initial_config).pack(pady=10)

    def setup_main_frame(self):
        """Interface principal do ChatPv."""
        # Frame principal
        self.main_frame = ctk.CTkFrame(self, fg_color="transparent")
        self.main_frame.pack(pady=10, padx=10, fill="both", expand=True)

        # Exibição de mensagens
        self.messages_frame = ctk.CTkScrollableFrame(self.main_frame, width=580, height=400, fg_color="#2A2A2A")
        self.messages_frame.pack(pady=10, padx=10, fill="both", expand=True)

        # Entrada de mensagem
        self.input_frame = ctk.CTkFrame(self.main_frame, corner_radius=10, fg_color="#2A2A2A")
        self.input_frame.pack(fill="x", padx=10, pady=(0, 10))

        self.message_entry = ctk.CTkEntry(self.input_frame, placeholder_text="Digite sua mensagem...")
        self.message_entry.pack(side="left", fill="x", expand=True, padx=(0, 10))
        self.message_entry.bind("<Return>", self.send_message)

        self.send_button = ctk.CTkButton(self.input_frame, text="Enviar", command=self.send_message)
        self.send_button.pack(side="right", padx=(0, 10))

        # Menu inferior centralizado
        self.menu_frame = ctk.CTkFrame(self, fg_color="transparent")
        self.menu_frame.pack(side="bottom", pady=5)

        upload_button = ctk.CTkButton(self.menu_frame, text="Upload de Arquivo", command=self.upload_file)
        upload_button.grid(row=0, column=0, padx=10)

        notifications_button = ctk.CTkButton(self.menu_frame, text=r"Bloquear/Desbloquear Notificações", command=self.toggle_notifications)
        notifications_button.grid(row=0, column=1, padx=10)
        

        # Centralizar os botões
        self.menu_frame.grid_columnconfigure(0, weight=1)
        self.menu_frame.grid_columnconfigure(1, weight=1)

        threading.Thread(target=self.monitor_messages, daemon=True).start()
        self.start_message_monitoring()


    def confirm_initial_config(self):
        """Confirmação das informações iniciais e conexão com MongoDB."""
        uri = self.uri_entry.get()
        db_name = self.database_entry.get()
        collection_name = self.collection_entry.get()
        encryption_key = self.encryption_key_entry.get()
        username = self.username_entry.get()
        password = self.password_entry.get()

        if not all([uri, db_name, collection_name, encryption_key, username, password]):
            messagebox.showerror("Erro", "Todos os campos são obrigatórios!")
            return

        try:
            encryption_key_bytes = binascii.unhexlify(encryption_key)
            if len(encryption_key_bytes) != 16:
                raise ValueError("A chave de criptografia deve ter 16 bytes (128 bits).")
        except binascii.Error:
            messagebox.showerror("Erro", "Chave de criptografia inválida. Use um formato hexadecimal.")
            return

        self.nome_usuario = username
        self.encryption_key = encryption_key_bytes
        self.UserMSG = username

        try:
            # Salvar todos os valores no keyring
            keyring.set_password("ChatPv", "MongoDB_URI", uri)
            keyring.set_password("ChatPv", "MongoDB_Database", db_name)
            keyring.set_password("ChatPv", "MongoDB_Collection", collection_name)
            keyring.set_password("ChatPv", "Encryption_Key", encryption_key)
            keyring.set_password("ChatPv", "MongoDB_Username", username)
            keyring.set_password("ChatPv", "MongoDB_Password", password)

            # Usar a senha para configurar o URI
            uri = uri.replace("passawordhere", password)
            self.client = MongoClient(uri)
            self.db = self.client[db_name]

            if collection_name not in self.db.list_collection_names():
                messagebox.showerror("Erro", "A coleção especificada não existe na base de dados.")
                return

            self.collection = self.db[collection_name]
            self.collection.create_index([("createdAt", 1)], expireAfterSeconds=10)
            messagebox.showinfo("Conexão", "Conexão com MongoDB realizada com sucesso!")
            self.initial_frame.destroy()
            self.setup_main_frame()

        except errors.OperationFailure as e:
            if "authentication failed" in str(e).lower():
                self.handle_wrong_password()
            else:
                messagebox.showerror("Erro de Conexão", f"Erro ao conectar ao MongoDB: {str(e)}")
        except Exception as e:
            messagebox.showerror("Erro", f"Erro inesperado: {str(e)}")

    def get_config_value(self, key):
        """Recupera valores de configuração armazenados com segurança."""
        return keyring.get_password("ChatPv", key)

    def handle_wrong_password(self):
        """Gerencia tentativas erradas de senha e bloqueio."""
        self.senha_incorreta += 1
        if self.senha_incorreta >= 3:
            self.bloquear_programa()
        else:
            messagebox.showerror(
                "Senha Incorreta",
                f"Tentativa {self.senha_incorreta} de 3. Verifique suas credenciais."
            )
            self.write_temp_file(self.senha_incorreta)

    def bloquear_programa(self):
        """Bloqueia o acesso por 10 minutos e salva o estado."""
        self.bloqueado_ate = time.time() + 600  # 10 minutos
        with open(self.caminho_arquivo_bloqueio, "w") as arquivo_bloqueio:
            arquivo_bloqueio.write(str(self.bloqueado_ate))
        messagebox.showerror(
            "Acesso Bloqueado",
            "Múltiplas tentativas de senha incorretas. O acesso está bloqueado por 10 minutos."
        )
        os._exit(0)

    def verify_and_close_if_locked(self):
        """Verifica se há um bloqueio ativo ao iniciar o programa."""
        if os.path.exists(self.caminho_arquivo_bloqueio):
            try:
                with open(self.caminho_arquivo_bloqueio, "r") as arquivo_bloqueio:
                    conteudo = arquivo_bloqueio.read()
                    if conteudo:
                        horario_bloqueio = float(conteudo)
                        horario_atual = time.time()
                        if horario_atual < horario_bloqueio:
                            minutos_restantes = int((horario_bloqueio - horario_atual) / 60)
                            messagebox.showerror(
                                "Acesso Bloqueado",
                                f"O acesso está bloqueado. Tente novamente em {minutos_restantes} minutos."
                            )
                            os._exit(0)
            except Exception as e:
                messagebox.showerror("Erro", f"Erro ao verificar bloqueio: {str(e)}")
            finally:
                # Certifica-se de que o arquivo está fechado antes de tentar removê-lo
                if os.path.exists(self.caminho_arquivo_bloqueio):
                    try:
                        os.remove(self.caminho_arquivo_bloqueio)  # Remove o bloqueio expirado
                    except PermissionError as pe:
                        messagebox.showerror(
                            "Erro de Permissão",
                            "Não foi possível remover o arquivo de bloqueio. Por favor, feche programas que possam estar utilizando-o."
                        )

    def write_temp_file(self, value):
        """Escreve no arquivo temporário o contador de tentativas."""
        with open(self.caminho_arquivo_tmp, 'w') as arquivo_tmp:
            arquivo_tmp.write(str(value))


    def on_closing(self):
        """Intercepta o fechamento da janela e realiza limpeza."""
        if messagebox.askokcancel("Sair", "Tem certeza que deseja fechar o programa?"):
            self.clean_up()
            self.destroy()

    def clean_up(self):
        """Remove todos os resquícios (dados temporários)."""
        if os.path.exists(self.temp_dir):
            shutil.rmtree(self.temp_dir)
            
    def send_message(self, event=None):
        """Envia uma mensagem para o MongoDB."""
        message = self.message_entry.get().strip()
        if not message:
            return

        encrypted_message = self.encrypt_message(message)
        self.collection.insert_one({
            "nome": self.nome_usuario,
            "mensagem": encrypted_message,
            "createdAt": datetime.now(timezone.utc),
        })
        self.message_entry.delete(0, END)

    def upload_file(self):
        """Upload de arquivos."""
        file_path = filedialog.askopenfilename()
        if file_path:
            file_name = file_path.split("/")[-1]
            with open(file_path, "rb") as file:
                file_data = file.read()
            # Insere no MongoDB
            doc_id = self.collection.insert_one({
                "nome": self.nome_usuario,
                "arquivo": Binary(file_data),
                "arquivo_nome": file_name,
                "createdAt": datetime.now(timezone.utc),
            }).inserted_id
            # Adicionar ao conjunto de mensagens exibidas
            self.mensagens_exibidas.add(str(doc_id))
            # Exibir mensagem na interface com o botão de download
            self.display_message(self.nome_usuario, f"Arquivo {file_name} enviado.", file_name, file_data)
            
    def start_message_monitoring(self):
        """Inicia o monitoramento de mensagens em uma thread separada."""
        thread = threading.Thread(target=self.monitor_messages, daemon=True)  # Garantindo o daemon=True
        thread.start()


    def monitor_messages(self):
        """Monitora as mensagens na database e exibe na interface."""
        while True:
            try:
                # Recupera mensagens ordenadas por data
                messages = self.collection.find().sort("createdAt", 1)
                for msg in messages:
                    msg_id = str(msg["_id"])
                    if msg_id not in self.mensagens_exibidas:
                        self.mensagens_exibidas.add(msg_id)

                        # Exibe mensagem descriptografada
                        if "mensagem" in msg:
                            decrypted_message = self.decrypt_message(msg["mensagem"])
                            self.safe_display_message(msg["nome"], decrypted_message)
                        elif "arquivo_nome" in msg:
                            self.safe_display_message(
                                msg["nome"],
                                f"Arquivo {msg['arquivo_nome']} enviado.",
                                msg["arquivo_nome"],
                                msg["arquivo"]
                            )
            except Exception as e:
                print(f"Erro ao monitorar mensagens: {e}")

            time.sleep(1)


    def safe_display_message(self, sender, message, file_name=None, file_data=None):
        """Adiciona mensagens à interface de forma segura no contexto principal."""
        self.messages_frame.after(0, self.display_message, sender, message, file_name, file_data)


    def display_message(self, sender, message, file_name=None, file_data=None):
        """Exibe mensagens na interface com horário, quebra de texto e notificações para mensagens de outros usuários."""
        # Obtém o horário de Brasília
        brasilia_timezone = pytz.timezone("America/Sao_Paulo")
        current_time = datetime.now(brasilia_timezone).strftime("%H:%M:%S")

        # Formata a mensagem
        mensagem_formatada = f"{current_time} | {sender}: {message}"

        # Frame da mensagem
        message_frame = ctk.CTkFrame(self.messages_frame, corner_radius=10, fg_color="transparent")
        message_frame.pack(fill="x", padx=10, pady=5)

        # Configurar o texto da mensagem com quebras automáticas
        message_label = ctk.CTkLabel(
            message_frame,
            text=mensagem_formatada,
            anchor="w",
            justify="left",  # Ajusta o alinhamento do texto
            wraplength=550,  # Define a largura máxima antes de quebrar o texto
        )
        message_label.pack(fill="x", padx=10, pady=5)

        # Botão de download, se for um arquivo
        if file_name and file_data:
            download_button = ctk.CTkButton(
                message_frame,
                text="Baixar",
                width=70,
                command=lambda: self.download_file(file_data, file_name),
            )
            download_button.pack(side="right", padx=5)

        # Adicionar lógica de notificações para mensagens de outros usuários
        try:
            remetente = sender.strip()  # Usa diretamente o `sender` como remetente

            # Exibe notificações somente para mensagens de outros usuários
            if remetente != self.UserMSG:  # Certifique-se de que `self.UserMSG` está corretamente configurado
                if not self.bloquear_notificacoes:
                    notification.notify(
                        title="Nova Mensagem",
                        message=f"{remetente}: {message}",
                        timeout=5,
                        app_icon=None,
                        toast=True,
                    )
        except Exception as e:
            print(f"Erro ao exibir notificação: {e}")

        # Forçar a rolagem para o final
        self.messages_frame.update_idletasks()
        self.messages_frame._parent_canvas.yview_moveto(1)



    def send_message(self, event=None):
        """Envia uma mensagem para o MongoDB."""
        message = self.message_entry.get().strip()
        if not message:
            return

        # Criptografar a mensagem antes de enviar
        encrypted_message = self.encrypt_message(message)

        self.collection.insert_one({
            "nome": self.nome_usuario,
            "mensagem": encrypted_message,
            "createdAt": datetime.now(timezone.utc),
        })
        self.message_entry.delete(0, END)

    def download_file(self, file_data, file_name):
        """Faz o download do arquivo recebido."""
        save_path = filedialog.asksaveasfilename(initialfile=file_name)
        if save_path:
            with open(save_path, "wb") as f:
                f.write(file_data)

    def encrypt_message(self, message):
        """Criptografa uma mensagem usando AES."""
        cipher = AES.new(self.encryption_key, AES.MODE_GCM)
        ciphertext, tag = cipher.encrypt_and_digest(pad(message.encode(), AES.block_size))
        return base64.b64encode(cipher.nonce + tag + ciphertext).decode()

    def decrypt_message(self, encrypted_message):
        """Descriptografa uma mensagem criptografada."""
        encrypted_data = base64.b64decode(encrypted_message)
        nonce, tag, ciphertext = encrypted_data[:16], encrypted_data[16:32], encrypted_data[32:]
        cipher = AES.new(self.encryption_key, AES.MODE_GCM, nonce=nonce)
        return unpad(cipher.decrypt_and_verify(ciphertext, tag), AES.block_size).decode()

    def toggle_notifications(self):
        """Alterna notificações."""
        self.bloquear_notificacoes = not self.bloquear_notificacoes
        status = "desbloqueadas" if not self.bloquear_notificacoes else "bloqueadas"
        self.display_message("Sistema", f"Notificações {status}.")

    def display_error(self, title, message):
        """Exibe uma mensagem de erro."""
        print(f"{title}: {message}")

if __name__ == "__main__":
    app = ChatApplication()
    app.mainloop()
