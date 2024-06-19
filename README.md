# CP-ChatPV
É um projeto de um chat privado com criptografia e privacidade total.

# Como usar? 😅

1. Baixe os arquivos e bibliotecas nessesarias.
2. Crie uma database no MongoDB e configure para o IP 0.0.0.0
3. O nome da database deve ser PV e o da coleção deve ser PV1, mas se você quiser mudar você pode mudar no codigo python.
   
![image](https://github.com/UserNotfoundR/CP-ChatPV/assets/128847349/fcc565fc-6bc6-439b-83c4-719165ef3e91)

4. Defina os valores **PYTHON_CRIPTO_KEY_HEX** e **PYTHON_MONGODB_KEY** nas variaveis de ambiente.
 
   -A chave de cripitografia deve ser de 32 Bytes
   
   -**PYTHON_MONGODB_KEY** se refere ao endereço da sua database que o mongoDB forneceu e copie oque o mongoDB te deu e tire os <> e mude **password** para **passwordhere** aqui é um 
   exemplo de como deve ficar:
   ```mongodb+srv://user:passawordhere@cluster0.9k2dal2.mongodb.net/?retryWrites=true```
6. Na hora de executar ele vai pedir a senha do endereço, por isso do **passwordhere** para não espalhar sua senha.
   
![image](https://github.com/UserNotfoundR/CP-ChatPV/assets/128847349/523b2fb3-a059-4c82-8930-20e24a080c21)

6. Compartilhe a database, senha e chave com as pessoas que você quer falar privadamente.

Recomendo compilar para um PE antes de mandar para outras pessoas, por questão de portabilidade.
# Avisos ⚠️

O codigo tem uma função que salva a quantidade de vezes que você errou a senha se você errou 3 o codígo vai bloquar o seu uso por 10 minutos e depois vai ser liberado para mais três tentativas.
![image](https://github.com/UserNotfoundR/CP-ChatPV/assets/128847349/9228e637-d6a1-4473-a3ef-bfe8f436960f)

