import tkinter as tk
import tkinter
from tkinter import simpledialog, messagebox, filedialog
from pymongo import MongoClient, errors
from datetime import datetime
import pytz
import threading
from plyer import notification
import os
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from bson.binary import Binary
import base64
import binascii
import time
import stat

class ChatApplication:
    def __init__(self):
        self.sec_key_hex = os.environ.get('PYTHON_CRIPTO_KEY_HEX')
        self.sec_mongodb_key = os.environ.get('PYTHON_MONGODB_KEY')
        self.sec_senha = os.environ.get('PYTHON_SENHA')
        self.sec_key = binascii.unhexlify(self.sec_key_hex)
        
        self.caminho_arquivo_tmp = 'senha_incorreta.tmp'
        self.bloquear_som = False
        self.bloquear_notificacoes = False
        self.mensagens_exibidas = set()
        
        self.check_temp_files()
        self.senha_incorreta3 = self.read_temp_file()
        
        self.nome = os.getlogin()
        self.UserMSG = self.nome
        
        self.verify_and_close_if_locked()
        self.senha_mongodb = self.prompt_mongodb_password()
        self.setup_mongodb_connection()
        
        self.setup_gui()
        
    def check_temp_files(self):
        if not os.path.exists(self.caminho_arquivo_tmp):
            with open(self.caminho_arquivo_tmp, 'w') as arquivo_tmp:
                arquivo_tmp.write('0')

    def read_temp_file(self):
        with open(self.caminho_arquivo_tmp, 'r') as arquivo_tmp:
            return int(arquivo_tmp.read())
    
    def write_temp_file(self, value):
        with open(self.caminho_arquivo_tmp, 'w') as arquivo_tmp:
            arquivo_tmp.write(str(value))
            
    def bloquear_programa(self):
        self.write_temp_file(0)
        with open('bloqueio.tmp', 'w') as arquivo_bloqueio:
            arquivo_bloqueio.write(str(time.time()))
    
        permissoes = stat.S_IRUSR | stat.S_IWUSR | stat.S_IXUSR
        os.chmod(self.caminho_arquivo_tmp, permissoes)
        os.chmod('bloqueio.tmp', permissoes)
    
        messagebox.showerror("Erro", "O acesso foi bloqueado devido a múltiplas tentativas de senha incorretas. :)")
        os._exit(0)
    
    def verify_and_close_if_locked(self):
        caminho_arquivo_bloqueio = 'bloqueio.tmp'
    
        if os.path.exists(caminho_arquivo_bloqueio):
            with open(caminho_arquivo_bloqueio, 'r') as arquivo_bloqueio:
                conteudo_arquivo = arquivo_bloqueio.read()
                if conteudo_arquivo:
                    horario_bloqueio = float(conteudo_arquivo)
                    horario_atual = time.time()
                    if horario_atual - horario_bloqueio < 600:
                        messagebox.showerror("Erro", "O acesso foi bloqueado devido a múltiplas tentativas de senha incorretas. Tente novamente em 10 minutos.")
                        os._exit(0)
    
    def exibir_erro(self, mensagem):
        messagebox.showerror("Erro", mensagem)
        os._exit(0)
    
    def exibir_erro_senha_incorreta(self):
        tkinter.messagebox.showerror("Erro", "Senha do MongoDB incorreta.")
        os._exit(0)
    
    def prompt_mongodb_password(self):
        root = tk.Tk()
        root.withdraw()
        senha = simpledialog.askstring("Senha MongoDB", "Digite a senha do MongoDB:", show='*')
        if senha is None:
            os._exit(0)
        return senha
    
    def setup_mongodb_connection(self):
        if self.senha_mongodb:
            self.sec_mongodb_key = self.sec_mongodb_key.replace("passawordhere", self.senha_mongodb)
            try:
                self.client = MongoClient(self.sec_mongodb_key)
                self.db = self.client.admin
                self.db.command('ping')
            except errors.OperationFailure as e:
                if self.senha_incorreta3 > 2:
                    self.bloquear_programa()
                elif "bad auth" in str(e):
                    self.senha_incorreta3 += 1
                    self.write_temp_file(self.senha_incorreta3)
                    self.exibir_erro_senha_incorreta()
    
    def conectar_mongodb(self, uri):
        try:
            return MongoClient(uri)
        except errors.OperationFailure as e:
            if "bad auth" in str(e):
                self.exibir_erro_senha_incorreta()
    
    def alternar_bloqueio(self):
        self.bloquear_som = not self.bloquear_som
        self.bloquear_notificacoes = self.bloquear_som
    
        if self.bloquear_som:
            self.bloqueio_button.config(text="Desbloquear Notificações")
        else:
            self.bloqueio_button.config(text="Bloquear Som e Notificações")
    
    def exibir_mensagem(self, mensagem_formatada):
        remetente = mensagem_formatada.split()[3]
        remetente = remetente.rstrip(':')
        if remetente != self.UserMSG:
            if not self.bloquear_notificacoes:
                notification.notify(
                    title="Nova Mensagem",
                    message=mensagem_formatada,
                    timeout=5,
                    app_icon=None,
                    toast=True,
                )
        self.mensagens_text.insert(tk.END, mensagem_formatada + "\n")
        self.scroll_para_baixo()
    
    def scroll_para_baixo(self):
        self.mensagens_text.yview(tk.END)
    
    def formatar_horario(self, horario_utc):
        fuso_horario_local = pytz.timezone('America/Sao_Paulo')
        horario_local = horario_utc.astimezone(fuso_horario_local)
        return horario_local.strftime("%d/%m %H:%M")
    
    def criptografar_mensagem(self, mensagem):
        cipher = AES.new(self.sec_key, AES.MODE_CBC)
        mensagem = pad(mensagem.encode(), AES.block_size)
        iv = cipher.iv
        mensagem_cifrada = cipher.encrypt(mensagem)
        return base64.b64encode(iv + mensagem_cifrada).decode()
    
    def descriptografar_mensagem(self, mensagem_cifrada):
        mensagem_cifrada = base64.b64decode(mensagem_cifrada)
        iv = mensagem_cifrada[:AES.block_size]
        cipher = AES.new(self.sec_key, AES.MODE_CBC, iv)
        mensagem = cipher.decrypt(mensagem_cifrada[AES.block_size:])
        return unpad(mensagem, AES.block_size).decode()
    
    def ler_mensagens(self):
        try:
            self.mensagens_text.config(state=tk.NORMAL)
            for doc in self.collection.find().sort('_id', -1):
                mensagem_id = str(doc['_id'])
                if mensagem_id not in self.mensagens_exibidas:
                    if 'nome' in doc:
                        horario_formatado = self.formatar_horario(doc['createdAt'])
                        if 'imagem_nome' in doc:
                            imagem_nome = doc['imagem_nome']
                            mensagem_formatada = f"{horario_formatado} - {doc['nome']}: {imagem_nome} (clique para baixar)"
                            mensagem_text_id = self.mensagens_text.index(tk.END)
                            mensagem_text_id = '{}-1c'.format(mensagem_text_id)
                            self.mensagens_text.insert(tk.END, mensagem_formatada, 'link')
                            self.mensagens_text.tag_bind('link', '<Button-1>', lambda event, link=doc['imagem']: self.download_imagem(link, imagem_nome))
                            self.mensagens_text.insert(tk.END, '\n')
                        else:
                            mensagem_descrição = doc['mensagem']
                            mensagem_decifrada = self.descriptografar_mensagem(mensagem_descrição)
                            mensagem_formatada = f"{horario_formatado} - {doc['nome']}: {mensagem_decifrada}"
                            self.exibir_mensagem(mensagem_formatada)
                        self.mensagens_exibidas.add(mensagem_id)
                    else:
                        print("Documento sem campo 'nome':", doc)
            self.mensagens_text.config(state=tk.DISABLED)
            self.scroll_para_baixo()
        except Exception as e:
            print("Erro ao ler mensagens:", e)
    
    def monitorar_mensagens(self):
        while True:
            self.ler_mensagens()
    
    def enviar_mensagem(self, nome, mensagem, imagem=None, imagem_nome=None):
        try:
            doc = {'nome': nome, 'createdAt': datetime.now()}
            if imagem:
                with open(imagem, "rb") as f:
                    imagem_data = f.read()
                doc['imagem'] = Binary(imagem_data)
                doc['imagem_nome'] = imagem_nome
            else:
                mensagem_cifrada = self.criptografar_mensagem(mensagem)
                doc['mensagem'] = mensagem_cifrada
            self.collection.insert_one(doc)
            print("Mensagem enviada com sucesso!")
        except Exception as e:
            print("Erro ao enviar mensagem:", e)
    
    def enviar(self, event=None):
        mensagem = self.mensagem_entry.get()
        if mensagem:
            self.enviar_mensagem(self.nome, mensagem)
            self.mensagem_entry.delete(0, tk.END)
    
    def selecionar_imagem(self):
        imagem_path = filedialog.askopenfilename(filetypes=[
            ("All Files", "*.*")
        ])
        if imagem_path:
            imagem_nome = os.path.basename(imagem_path)
            self.enviar_mensagem(self.nome, "", imagem=imagem_path, imagem_nome=imagem_nome)
    
    def download_imagem(self, imagem_data, nome):
        with open(nome, "wb") as f:
            f.write(imagem_data)
        print("Imagem ou arquivo baixado com sucesso!")
    
    def iniciar_monitoramento(self):
        threading.Thread(target=self.monitorar_mensagens, daemon=True).start()
    
    def on_closing(self):
        self.root.destroy()
        os._exit(0)
    
    def setup_gui(self):
        self.client = self.conectar_mongodb(self.sec_mongodb_key)
        if self.client:
            self.db = self.client['Pv']
            self.collection = self.db['pv1']
    
            self.root = tk.Tk()
            self.root.title("ChatPv")
    
            self.root.configure(bg="#36393f")
            self.root.geometry("400x400")
            self.root.resizable(width=False, height=False)
            self.root.protocol("WM_DELETE_WINDOW", self.on_closing)
    
            self.bloqueio_button = tk.Button(self.root, text="Bloquear Som e Notificações", command=self.alternar_bloqueio, bg="#40444b", fg="white")
            self.bloqueio_button.pack(pady=5)
    
            self.mensagem_entry = tk.Entry(self.root, width=50, bg="#40444b", fg="white", insertbackground="white")
            self.mensagem_entry.pack(side=tk.BOTTOM, fill=tk.X, padx=10, pady=5)
            self.mensagem_entry.bind("<Return>", self.enviar)
    
            self.enviar_button1 = tk.Button(self.root, text="Enviar", command=self.enviar, bg="#40444b", fg="white")
            self.enviar_button1.pack(side=tk.BOTTOM, pady=5)
    
            self.enviar_button = tk.Button(self.root, text="Enviar arquivo ou imagem", command=self.selecionar_imagem, bg="#40444b", fg="white")
            self.enviar_button.pack(side=tk.BOTTOM, pady=5)
    
            self.mensagens_text = tk.Text(self.root, width=50, height=20, bg="#40444b", fg="white", state=tk.DISABLED)
            self.mensagens_text.pack(pady=5, padx=10)
    
            self.iniciar_monitoramento()
    
            self.root.mainloop()
    
if __name__ == "__main__":
    app = ChatApplication()
