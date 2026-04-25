# Zabezpečená komunikace
- autoři: Gabriel Madový (283573), Petr Věříš (283559), Oliver Synak (281728), Donát Szabó (283384)

## Popis
- jednoduchý chatovací program
- k serveru se připojí klienti a mohou chatovat ve skupině
- možnost simulovat man-in-the-middle útok pomocí módu ``attacker``
    - při jeho spuštění se program chová jako klient s tím rozdílem, že je veškerá příchozí a odchozí komunikace přeposílána modulu útočníka

## Návod
### Spuštění a připojení
- server
    - ``python main.py server [adresa ze které bude přijímat přopojení] [port]``
- klient
    - ``python main.py client [adresa serveru] [port][jméno instance]``
    - př. ``python main.py client 127.0.0.1 12345 skveleuzivatelskejmeno``
- útočník
    - ``python main.py attacker [adresa serveru] [port] [jméno instance]`` 

### Vyměna RSA klíčů
- klient
    - po úspěšném připojení k serveru použít příkaz ``rsa``
        - pokud existuje souboru ``[jméno instance]_client_key.json``, tak z něj načte vlastní uložené veřejný a privátní klíč
        - pokud soubor neexistuje, vygeneruje nové klíče a uloží je do souboru
    - klient se serverem si navzájem vymění veřejné klíče
        - pokud existuje soubor ``[jméno instance]_server_key.json``, tak z něj načte uložený veřejný klíč serveru a porovná je s obdrženým klíčem, pakliže se neshodují, odmítne jejich přijetí další komunikaci se serverem
        - pokud soubor neexistuje, obdržený klíč uloží do souboru
    - při úspěchu je klient připraven na výměny symetrických klíčů pomocí protokolu Diffie-Hellman
- server
    - pokud existuje soubor ``server_key.json``, tak z něj načte veřejný a privátní klíč serveru
    - pokud neexistuje, klíče vygeneruje a uloží je do souboru
- útočník
    - při výměně klíčů podstrčí klientovi a serveru vlastní veřejný klíč
    - selže, pokud má klient uložený veřejný klíč serveru z předešlé relace, která nebyla kompromitována

### Diffie-Hellman & KDF
Tento modul zajišťuje bezpečné ustavení sdíleného tajemství a následnou derivaci 256-bitového symetrického klíče pro AES.

**Technická specifikace:**
- **Parametry:** Protokol využívá fixní parametry **RFC 3526 MODP Group 14** (2048-bitové bezpečné prvočíslo $p$ a generátor $g=2$).
- **KDF (Key Derivation):** Surové tajemství (shared secret) je transformováno na finální klíč pomocí funkce **HKDF** (HMAC-based Key Derivation Function) s algoritmem **SHA-256**.
- **Bezpečnost:** Implementace **Ephemeral Diffie-Hellman (DHE)** zajišťuje *Perfect Forward Secrecy*. Veřejné klíče jsou validovány proti útokům na malé podgrupy (*Small Subgroup Attacks*).

**Klíčové funkce:**
- `DHLogic.py`:
  - `generate_private_key(p)`: Generuje kryptograficky bezpečný privátní exponent.
  - `is_valid_public_key(public_key, p)`: Ověřuje, zda přijatý veřejný klíč leží v bezpečném intervalu $(1, p-1)$.
  - `derive_aes_key(shared_secret)`: Provádí derivaci 32-bajtového klíče pomocí HKDF-SHA256.
- `DHNetwork.py`:
  - `build_init_packet()`: Sestavuje iniciační paket `DH_INIT` pro zahájení výměny.
  - `process_init_packet()` & `process_accept_packet()`: Zpracovávají síťovou logiku handshaku a provádějí finální výpočet klíče.

**Průběh v aplikaci:**
- **klient**
  - po úspěšné výměně RSA klíčů použít příkaz ``dh``
  - proběhne handshake; parametry jsou podepsány RSA pro eliminaci MitM útoků
  - při úspěchu bude následující komunikace zašifrována pomocí AES-GCM
- **útočník**
  - pokusí se vyměnit klíče s oběma stranami; je úspěšný pouze pokud není handshake autentizován RSA (v opačném případě RSA podpis odhalí manipulaci)
### AES-GCM
- klient
    -  po úspěšné výměně klíčů pomocí příkazu ``dh`` se vytvoří symetrický AES session key
    - všechny následující zprávy se odesílají šifrované pomocí AES-GCM
    - při odeslání zprávy:
        - vygeneruje se náhodný nonce -> zpráva se zašifruje -> vytvoří se packet ve tvaru: ``length | nonce | tag | ciphertext``
    - při přijetí zprávy:
        - zpráva se dešifruje pomocí AES klíče -> ověří se autentizační tag -> pokud ověření selže, zpráva se zahodí / pokud je validní, zobrazí se uživateli
- server
    - po úspěšném DH uchovává AES klíč pro každého klienta zvlášť
    - při přijetí zprávy od klienta:
        - zprávu dešifruje pomocí jeho AES klíče -> vytvoří novou zprávu ve tvaru ``port: zpráva``
    - při odeslání ostatním klientům:
        - zprávu znovu zašifruje AES klíčem daného klienta -> odešle ji jako nový packet
- útočník
    - vytvoří vlastní AES klíče s klientem i serverem
    - při komunikaci:
        - dešifruje zprávy od klienta i serveru
        - zobrazí jejich obsah
        - následně je znovu zašifruje a přepošle dál
    - při úspěchu může číst celou komunikaci bez toho, aby si toho klient nebo server všimli
    
### Chatování
- klient, útočník

### Ukončení
- server
    - kombinací Ctrl + C :)
- klient, útočník
    - příkazem ``exit``
