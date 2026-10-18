# Zabezpečená komunikace
- autoři: Gabriel Madový (283573), Petr Věříš (283559), Oliver Synak (281728), Donát Szabó (283384)

## Popis
- jednoduchý chatovací program, který slouží jako kryptografický playground
- k serveru se připojí klienti a mohou chatovat ve skupině
- komunikace je zabezpečena pomocí symetrického šifrování (AES-GCM), výměny klíčů (Diffie-Hellman s HKDF) a asymetrické autentizace (RSA)
- obsahuje integrovaného proxy útočníka pro demonstraci Man-in-the-Middle (MITM) útoků

## Návod
### Spuštění a připojení
- server
    - ``python main.py server [adresa ze které bude přijímat přopojení] [port]`` (př. ``python main.py server 127.0.0.1 8000``)
    - ve výchozím stavu se spouští v **bezpečném režimu** (vynucuje RSA ověření)
    - pro demonstraci zranitelnosti vůči útokům přidejte na konec parametr ``--unsecure``
- útočník (MITM Proxy)
    - ``python main.py attack [adresa cílového serveru] [port cílového serveru]`` (př. ``python main.py attack 127.0.0.1 8000``)
    - útočník automaticky otevře naslouchací port o číslo vyšší (např. 8001), na který se budou připojovat oběti (klienti)
- klient
    - ``python main.py client [adresa serveru nebo útočníka] [port] [jméno instance]``
    - př. přímé připojení na server: ``python main.py client 127.0.0.1 8000 klient1``
    - př. připojení přes proxy útočníka: ``python main.py client 127.0.0.1 8001 klient1``
    - pro zranitelný režim přidejte na konec parametr ``--unsecure``

### Výměna RSA klíčů (Autentizace)
- klient
    - po úspěšném připojení k serveru použít příkaz ``rsa``
        - pokud existuje soubor ``[jméno instance]_client_key.json``, tak z něj načte vlastní uložené veřejný a privátní klíč
        - pokud soubor neexistuje, vygeneruje nové klíče a uloží je do souboru
    - klient se serverem si navzájem vymění veřejné klíče
        - pokud existuje soubor ``[jméno instance]_server_key.json``, tak z něj načte uložený veřejný klíč serveru a porovná je s obdrženým klíčem, pakliže se neshodují, upozorní na možnost útoku identity
        - pokud soubor neexistuje, obdržený klíč uloží do souboru
    - při úspěchu je klient připraven na výměnu symetrických klíčů pomocí protokolu Diffie-Hellman
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
- *poznámka:* V režimu ``--unsecure`` se tento krok přeskakuje.

### Diffie-Hellman (Výměna šifrovacích klíčů)
- klient
    - po úspěšné výměně klíčů použít příkaz ``dh`` (nebo rovnou, pokud je spuštěno s ``--unsecure``)
    - v bezpečném režimu je DH zpráva podepsána RSA klíčem odesílatele, což zabraňuje její změně po cestě
    - z vygenerovaného sdíleného tajemství se pomocí HKDF odvodí finální 256-bitový AES klíč
    - při úspěchu bude následující komunikace zašifrována pomocí AES-GCM

### Chatování a Útoky
- klient
    - libovolný napsaný text se bezpečně zašifruje a odešle
    - odeslané zprávy se dešifrují na serveru a přeposílají zbytku připojených klientů
- útočník (pokud klienti komunikují přes něj)
    - příkaz ``attack`` - Zapne/vypne aktivní MITM útok. Útočník zachytí DH výměnu, podvrhne vlastní veřejné klíče a vyjedná si šifrování s oběma stranami. Následně transparentně dešifruje a vypisuje celou komunikaci. (Tento útok **uspěje pouze v režimu ``--unsecure``**, jinak RSA podpis útok matematicky odhalí a spojení okamžitě ukončí!)
    - příkaz ``tamper <text>`` - Útočník nahradí obsah další zachycené a dešifrované zprávy zadaným textem, znovu ji podvrženou zašifruje a pošle cíli.
    - příkaz ``spoof`` - Útočník začne generovat a rozesílat falešné zašifrované zprávy na obě strany.

### Ukončení
- server / útočník
    - kombinací Ctrl + C :) nebo příkazem ``exit``
- klient
    - příkazem ``exit``
