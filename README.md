# CP-ChatPV

Projeto de chat privado com criptografia e privacidade total.

## Como usar? 😅

1. Baixe os arquivos e bibliotecas necessárias.
2. Crie uma database no MongoDB e configure para o IP `0.0.0.0`.
3. O nome da database deve ser `PV` e o da coleção deve ser `PV1`. Se desejar, você pode alterar esses nomes no código Python.

   ![image](https://github.com/UserNotfoundR/CP-ChatPV/assets/128847349/fcc565fc-6bc6-439b-83c4-719165ef3e91)

4. Defina os valores **PYTHON_CRIPTO_KEY_HEX** e **PYTHON_MONGODB_KEY** nas variáveis de ambiente:
   
   - A chave de criptografia deve ter 32 bytes.
   - **PYTHON_MONGODB_KEY** se refere ao endereço da sua database fornecido pelo MongoDB. Copie o endereço fornecido, remova os `<` `>` e substitua `password` por `passwordhere`. Aqui está um exemplo:
   
     ```mongodb+srv://user:passwordhere@cluster0.9k2dal2.mongodb.net/?retryWrites=true```
   
5. Ao executar o código, ele pedirá a senha do endereço. Use `passwordhere` para não expor sua senha real.

   ![image](https://github.com/UserNotfoundR/CP-ChatPV/assets/128847349/523b2fb3-a059-4c82-8930-20e24a080c21)

6. Compartilhe a database, senha e chave com as pessoas com quem você quer se comunicar privadamente.

Recomendo compilar para um executável (PE) antes de enviar para outras pessoas, por questões de portabilidade.

## Avisos ⚠️

O código tem uma função que salva a quantidade de tentativas de senha erradas. Se você errar 3 vezes, o código bloqueará o uso por 10 minutos, após os quais você terá mais três tentativas.

   ![image](https://github.com/UserNotfoundR/CP-ChatPV/assets/128847349/9228e637-d6a1-4473-a3ef-bfe8f436960f)

Não há **compatibilidade garantida com Linux**. Bibliotecas e algumas partes do código precisarão ser **modificadas** se você quiser criar uma versão para Linux.

