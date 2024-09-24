import tkinter as tk
from tkinter import simpledialog, messagebox, filedialog
from pymongo import MongoClient, errors
from datetime import datetime, timezone
import pytz
import threading
from plyer import notification
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes
from bson.binary import Binary
import base64
import binascii
import os
import stat
import time
import tempfile
import keyring

class ChatApplication:
    def __init__(self):
        # Variáveis e configuração inicial
        self.mensagens_exibidas = set()
        self.bloquear_som = False
        self.bloquear_notificacoes = False
        self.senha_incorreta3 = 0
        self.bloqueado_ate = None
        self.temp_dir = tempfile.gettempdir()
        self.caminho_arquivo_tmp = os.path.join(self.temp_dir, 'senha_incorreta.tmp')
        self.caminho_arquivo_bloqueio = os.path.join(self.temp_dir, 'bloqueio.tmp')

        # O restante do código de inicialização
        self.prompt_for_info()
        self.check_temp_files()
        self.senha_incorreta3 = self.read_temp_file()
        self.UserMSG = self.nome
        self.verify_and_close_if_locked()
        self.senha_mongodb = self.prompt_mongodb_password()
        self.setup_mongodb_connection()
        self.setup_gui()

    def setup_gui(self):
        # Recupera as informações do keyring
        database_name = keyring.get_password("ChatApp", "database_name")
        collection_name = keyring.get_password("ChatApp", "collection_name")

        if self.client:
            self.db = self.client[database_name]
            self.collection = self.db[collection_name]

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

    def enviar(self, event=None):
        """
        Função que envia a mensagem quando o botão Enviar é pressionado ou quando a tecla Enter é pressionada.
        """
        mensagem = self.mensagem_entry.get()
        if mensagem:
            self.enviar_mensagem(self.nome, mensagem)
            self.mensagem_entry.delete(0, tk.END)

    def enviar_mensagem(self, nome, mensagem, imagem=None, imagem_nome=None):
        """
        Envia a mensagem para o MongoDB com o campo `createdAt`, garantindo que a mensagem tenha um TTL individual de 10 segundos.
        """
        try:
            # Criar o documento da mensagem com o campo `createdAt`
            doc = {'nome': nome, 'createdAt': datetime.now(timezone.utc)}  # Horário com timezone UTC
            if imagem:
                with open(imagem, "rb") as f:
                    imagem_data = f.read()
                doc['imagem'] = Binary(imagem_data)
                doc['imagem_nome'] = imagem_nome
            else:
                mensagem_cifrada = self.criptografar_mensagem(mensagem)
                doc['mensagem'] = mensagem_cifrada

            # Inserir o documento na coleção
            self.collection.insert_one(doc)
            print("Mensagem enviada com sucesso!")
        except Exception as e:
            print("Erro ao enviar mensagem:", e)

    def criptografar_mensagem(self, mensagem):
        # Recupera a chave de criptografia do keyring
        encryption_key = base64.b64decode(keyring.get_password("ChatApp", "encryption_key"))
        
        # Criação do cifrador GCM
        cipher = AES.new(encryption_key, AES.MODE_GCM)
        
        # Padding da mensagem e criptografia
        mensagem = pad(mensagem.encode(), AES.block_size)
        iv = cipher.nonce  # Nonce é o IV no modo GCM
        mensagem_cifrada, tag = cipher.encrypt_and_digest(mensagem)
        
        # Concatenando IV, mensagem cifrada e tag, e retornando em base64
        return base64.b64encode(iv + mensagem_cifrada + tag).decode()

    def descriptografar_mensagem(self, mensagem_cifrada):
        # Recupera a chave de criptografia do keyring
        encryption_key = base64.b64decode(keyring.get_password("ChatApp", "encryption_key"))
        
        # Decodifica a mensagem cifrada de base64
        mensagem_cifrada = base64.b64decode(mensagem_cifrada)
        
        # Separa o IV (nonce), a mensagem cifrada e a tag
        iv = mensagem_cifrada[:16]  # Tamanho do nonce/IV é 16 bytes
        tag = mensagem_cifrada[-16:]  # A tag está nos últimos 16 bytes
        mensagem_cifrada = mensagem_cifrada[16:-16]  # O texto cifrado está no meio
        
        # Descriptografar a mensagem usando o IV e a tag
        cipher = AES.new(encryption_key, AES.MODE_GCM, iv)
        
        # Tentar descriptografar e verificar a integridade com a tag
        mensagem = cipher.decrypt_and_verify(mensagem_cifrada, tag)
        
        # Remover o padding da mensagem
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
                            self.root.after(0, self.exibir_mensagem, mensagem_formatada)
                        else:
                            mensagem_descrição = doc['mensagem']
                            mensagem_decifrada = self.descriptografar_mensagem(mensagem_descrição)
                            mensagem_formatada = f"{horario_formatado} - {doc['nome']}: {mensagem_decifrada}"
                            self.root.after(0, self.exibir_mensagem, mensagem_formatada)
                        self.mensagens_exibidas.add(mensagem_id)
                    else:
                        # Exibir um alerta para o usuário se o campo 'nome' estiver ausente
                        self.root.after(0, messagebox.showerror, "Erro ao Ler Mensagens", "Uma mensagem foi encontrada sem o campo 'nome'.")
            self.mensagens_text.config(state=tk.DISABLED)
            self.scroll_para_baixo()
        except Exception as e:
            # Exibir um alerta para o usuário no caso de erros gerais
            self.root.after(0, messagebox.showerror, "Erro ao Ler Mensagens", f"Ocorreu um erro: {str(e)}")

    def formatar_horario(self, horario_utc):
        """
        Formata um horário UTC para o fuso horário local (America/Sao_Paulo).
        """
        fuso_horario_local = pytz.timezone('America/Sao_Paulo')
        horario_local = horario_utc.astimezone(fuso_horario_local)
        return horario_local.strftime("%d/%m %H:%M")

    def monitorar_mensagens(self):
        while True:
            self.ler_mensagens()

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

    def selecionar_imagem(self):
        imagem_path = filedialog.askopenfilename(filetypes=[
            ("All Files", "*.*")
        ])
        if imagem_path:
            imagem_nome = os.path.basename(imagem_path)
            self.enviar_mensagem(self.nome, "", imagem=imagem_path, imagem_nome=imagem_nome)

    def alternar_bloqueio(self):
        self.bloquear_som = not self.bloquear_som
        self.bloquear_notificacoes = self.bloquear_som

        if self.bloquear_som:
            self.bloqueio_button.config(text="Desbloquear Notificações")
        else:
            self.bloqueio_button.config(text="Bloquear Som e Notificações")

    def on_closing(self):
        """
        Esta função será chamada quando a janela for fechada.
        Ela encerra o aplicativo com segurança.
        """
        if messagebox.askokcancel("Sair", "Você quer sair do aplicativo?"):
            self.root.destroy()
            os._exit(0)

    def prompt_for_info(self):
        # Coleta as informações do usuário pela GUI
        self.root = tk.Tk()
        self.root.withdraw()  # Oculta a janela principal do Tkinter

        # Coletar a URI do MongoDB, nome da Database, Coleção e a Chave de Criptografia das Mensagens
        uri = simpledialog.askstring("Input", "Insira o URI do MongoDB:")
        database_name = simpledialog.askstring("Input", "Insira o nome da Base de Dados (Use exatamente o nome da database):")
        collection_name = simpledialog.askstring("Input", "Insira o nome da Coleção:")
        encryption_key = simpledialog.askstring("Input", "Insira a chave de criptografia das mensagens (em hexadecimal):")
        user_name = simpledialog.askstring("Input", "Insira o nome do usuário:")

        # Validação das entradas
        if not uri or not database_name or not collection_name or not user_name:
            messagebox.showerror("Erro", "URI, Base de Dados, Coleção e Nome de Usuário são obrigatórios.")
            os._exit(0)

        # Convertendo a chave hexadecimal para bytes
        try:
            encryption_key_bytes = binascii.unhexlify(encryption_key)
            if len(encryption_key_bytes) != 16:
                raise ValueError("A chave de criptografia deve ter 16 bytes (128 bits) de comprimento.")
        except (binascii.Error, ValueError) as e:
            messagebox.showerror("Erro", f"Chave de criptografia inválida: {str(e)}. Certifique-se de que está em formato hexadecimal.")
            os._exit(0)

        # Armazenar todas as informações no gerenciador de senhas de forma segura
        keyring.set_password("ChatApp", "mongodb_uri", uri)
        keyring.set_password("ChatApp", "database_name", database_name)
        keyring.set_password("ChatApp", "collection_name", collection_name)
        keyring.set_password("ChatApp", "encryption_key", base64.b64encode(encryption_key_bytes).decode())
        keyring.set_password("ChatApp", "user_name", user_name)

        self.nome = user_name
        messagebox.showinfo("Sucesso", "Informações criptografadas e armazenadas no gerenciador seguro.")

        self.root.destroy()

    def setup_mongodb_connection(self):
        # Recuperar os dados do gerenciador seguro
        uri = keyring.get_password("ChatApp", "mongodb_uri")
        database_name = keyring.get_password("ChatApp", "database_name")
        collection_name = keyring.get_password("ChatApp", "collection_name")
        encryption_key = base64.b64decode(keyring.get_password("ChatApp", "encryption_key"))

        self.nome = keyring.get_password("ChatApp", "user_name")

        # Substituir a senha no URI
        uri = uri.replace("passawordhere", self.senha_mongodb)

        try:
            # Conectar ao MongoDB e garantir que o índice TTL seja configurado
            self.client = MongoClient(uri, tls=True, tlsAllowInvalidCertificates=False)  # Conexão segura TLS
            self.db = self.client[database_name]
            self.collection = self.db[collection_name]
            self.db.command('ping')
            print("Conexão bem-sucedida ao MongoDB!")
            
            # Criar o índice TTL para o campo `createdAt`, garantindo que as mensagens expirem em 10 segundos
            self.collection.create_index([('createdAt', 1)], expireAfterSeconds=10)
            print("Índice TTL configurado com expiração de 10 segundos.")

        except errors.InvalidURI as e:
            print("Erro de URI MongoDB:", e)
            messagebox.showerror("Erro", f"URI MongoDB inválida: {str(e)}")
            os._exit(0)
        except errors.OperationFailure as e:
            if self.senha_incorreta3 > 2:
                self.bloquear_programa()
            elif "bad auth" in str(e):
                self.senha_incorreta3 += 1
                self.write_temp_file(self.senha_incorreta3)
                self.exibir_erro_senha_incorreta()

    def prompt_mongodb_password(self):
        root = tk.Tk()
        root.withdraw()
        senha = simpledialog.askstring("Senha MongoDB", "Digite a senha do MongoDB:", show='*')
        if senha is None:
            os._exit(0)
        return senha

    def check_temp_files(self):
        if not os.path.exists(self.caminho_arquivo_tmp):
            with open(self.caminho_arquivo_tmp, 'w') as arquivo_tmp:
                arquivo_tmp.write('0')
        os.chmod(self.caminho_arquivo_tmp, stat.S_IRUSR | stat.S_IWUSR)  # Permissões restritas ao usuário

    def read_temp_file(self):
        with open(self.caminho_arquivo_tmp, 'r') as arquivo_tmp:
            return int(arquivo_tmp.read())

    def write_temp_file(self, value):
        with open(self.caminho_arquivo_tmp, 'w') as arquivo_tmp:
            arquivo_tmp.write(str(value))

    def bloquear_programa(self):
        self.write_temp_file(0)
        with open(self.caminho_arquivo_bloqueio, 'w') as arquivo_bloqueio:
            arquivo_bloqueio.write(str(time.time()))

        permissoes = stat.S_IRUSR | stat.S_IWUSR | stat.S_IXUSR
        os.chmod(self.caminho_arquivo_tmp, permissoes)
        os.chmod(self.caminho_arquivo_bloqueio, permissoes)

        messagebox.showerror("Erro", "O acesso foi bloqueado devido a múltiplas tentativas de senha incorretas.")
        os._exit(0)

    def verify_and_close_if_locked(self):
        if os.path.exists(self.caminho_arquivo_bloqueio):
            with open(self.caminho_arquivo_bloqueio, 'r') as arquivo_bloqueio:
                conteudo_arquivo = arquivo_bloqueio.read()
                if conteudo_arquivo:
                    horario_bloqueio = float(conteudo_arquivo)
                    horario_atual = time.time()
                    if horario_atual - horario_bloqueio < 600:
                        messagebox.showerror("Erro", "O acesso foi bloqueado. Tente novamente em 10 minutos.")
                        os._exit(0)

    def exibir_erro_senha_incorreta(self):
        tkinter.messagebox.showerror("Erro", "Senha do MongoDB incorreta.")
        os._exit(0)

    def iniciar_monitoramento(self):
        threading.Thread(target=self.monitorar_mensagens, daemon=True).start()

if __name__ == "__main__":
    app = ChatApplication()
