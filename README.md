# Gestão de direitos digitais

Este trabalho tem como objetivo o desenvolvimento de mecanismos de proteção de dados e comunicações num serviço de reprodução de música cliente-servidor, permitindo uma comunicação segura. 

Neste sentido, foi fornecida a estrutura base do serviço com algumas funções relativas aos protocolos de comunicação desprotegidos já implementadas, permitindo a reprodução de músicas sem qualquer tipo de segurança ou autenticação, tendo sido necessário desenvolver as capacidades de proteção da troca de informação, de autenticação, etc.


## Como Executar

1. Instalar o _ffplay_:

    ### [Linux](https://linuxize.com/post/how-to-install-ffmpeg-on-ubuntu-18-04/)

    1. Atualizar a lista de _packages_
        ```
        $ sudo apt update
        ```

    2. Instalar o FFmpeg
        ```
        $ sudo apt install ffmpeg
        ```


    ### [MacOS](https://steemit.com/mac/@manero666/how-to-install-ffmpeg-on-mac-osx-with-ffplay)

    1. Instalar o [HomeBrew](https://brew.sh)

    2. Verificar que tem a instalação do _Xcode_ em dia

    3. Instalar o _ffmpeg_ através do _HomeBrew_:
        ```
        $ brew install homebrew-ffmpeg/ffmpeg/ffmpeg
        ```

3. Criar um _Virtual Environment_:

    ```
    python3 -m venv venv
    ```

4. Instalar os requisitos:

    Se estiver no MacOS, é necessário instalar o _swig_, em caso contrário ignore a instrução seguinte

    Instalar o _swig_ através do _HomeBrew_:

        $ brew install swig

    Instalar os requisitos:

        $ source venv/bin/activate
        $ pip install -r ./client/requirements.txt
        $ pip install -r ./server/requirements.txt

5. ~~Encriptar as músicas em claro~~ (Não necessário):

    Na pasta [server/encrypted_catalog](server/encrypted_catalog) encontram-se as músicas encriptadas com as suas informações no ficheiro [server/file_info.txt](server/file_info.txt). Caso algum dos ficheiros na pasta mencionada ou o ficheiro das informações seja alterado/apagado, deve-se voltar a encriptar as músicas executando:
    
        $ cd server
        $ python3 file_encrypt.py



6. Correr os serviços:
    ```
    $ ./run.sh
    ``` 
## Detalhes

Todos os detalhes podem ser encontrados no [Relatório](/relatorio/SIO_P2_3.pdf).

## Nota

Classificação referente ao trabalho de grupo de **4.61** valores em 5.




