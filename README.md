# Zabezpečená komunikace
- autoři: Gabriel Madový (283573), Petr Věříš (283559), Oliver Synak (281728), Donát Szabó (283384)

## Popis
- jednoduchý chatovací program, který slouží jako kryptografický playground
- k serveru se připojí klienti a mohou chatovat ve skupině
- komunikace je zabezpečena pomocí symetrického šifrování (AES-GCM), výměny klíčů (Diffie-Hellman s HKDF) a asymetrické autentizace (RSA)
- obsahuje integrovaného proxy útočníka pro demonstraci Man-in-the-Middle (MITM) útoků

## Návod
### Instalace
- Python 3.10+
- ``pip install -r requirements.txt``

### Testy
- z kořenového adresáře repozitáře: ``python -m unittest discover -s Test -t .``

### Spuštění a připojení
- server
    - ``python main.py server [adresa ze které bude přijímat připojení] [port]`` (př. ``python main.py server 127.0.0.1 8000``)
    - ve výchozím stavu se spouští v **bezpečném režimu** (vynucuje RSA ověření)
    - pro demonstraci zranitelnosti vůči útokům přidejte parametr ``--unsecure``
- útočník (MITM proxy)
    - ``python main.py attack [adresa cílového serveru] [port cílového serveru]`` (př. ``python main.py attack 127.0.0.1 8000``)
    - útočník otevře naslouchací port o číslo vyšší (např. 8001) na adrese ``127.0.0.1``, na který se připojují oběti (klienti)
- klient
    - ``python main.py client [adresa serveru nebo útočníka] [port] [jméno instance]``
    - př. přímé připojení na server: ``python main.py client 127.0.0.1 8000 klient1``
    - př. připojení přes proxy útočníka: ``python main.py client 127.0.0.1 8001 klient1``
    - jméno instance je nepovinné (výchozí ``default``) a určuje názvy souborů s klíči
    - pro zranitelný režim přidejte parametr ``--unsecure``
- parametr ``--unsecure`` může stát kdekoliv; při chybných parametrech se vypíše nápověda (``python main.py -h``)
- soubory s klíči (``*.json``) se ukládají do **aktuálního pracovního adresáře**; při spuštění z jiného adresáře vznikne nová identita

### Výměna RSA klíčů (autentizace, jen bezpečný režim)
- klient
    - po připojení k serveru použít příkaz ``rsa`` (v režimu ``--unsecure`` se tento krok přeskakuje)
        - pokud existuje soubor ``[jméno instance]_client_key.json``, načte z něj vlastní veřejný a privátní klíč
        - pokud soubor neexistuje, vygeneruje nové klíče a uloží je do souboru
    - klient se serverem si vymění veřejné klíče
        - pokud existuje soubor ``[jméno instance]_server_key.json``, porovná uložený veřejný klíč serveru s obdrženým; pokud se neshodují, upozorní na možný útok a klíč nepřijme
        - pokud soubor neexistuje, obdržený klíč uloží (trust on first use)
- server
    - při startu načte veřejný a privátní klíč ze souboru ``server_key.json``, nebo je vygeneruje a uloží
- útočník
    - pakety ``RSA_INIT`` přeposílá beze změny; RSA klíče nepodvrhuje
- poškozený soubor s klíči se ohlásí chybou, aplikace ho nepřepíše

### Diffie-Hellman & KDF
Tento modul zajišťuje ustavení sdíleného tajemství a následnou derivaci 256-bitového symetrického klíče pro AES.

**Technická specifikace:**
- **Parametry:** Protokol využívá fixní parametry **RFC 3526 MODP Group 14** (2048-bitové bezpečné prvočíslo $p$ a generátor $g=2$). Odpovídající strana odmítne ``DH_INIT`` s jinými parametry.
- **KDF (Key Derivation):** Surové tajemství (shared secret) je transformováno na finální klíč pomocí funkce **HKDF** s algoritmem **SHA-256**.
- **Bezpečnost:** Implementace **Ephemeral Diffie-Hellman (DHE)** zajišťuje *Perfect Forward Secrecy*. Veřejné klíče jsou validovány proti útokům na malé podgrupy (*Small Subgroup Attacks*).

**Klíčové funkce:**
- `DHLogic.py`:
  - `generate_private_key(p)`: Generuje kryptograficky bezpečný privátní exponent.
  - `is_valid_public_key(public_key, p)`: Ověřuje, zda přijatý veřejný klíč leží v bezpečném intervalu $(1, p-1)$.
  - `derive_aes_key(shared_secret)`: Provádí derivaci 32-bajtového klíče pomocí HKDF-SHA256.
- `DHNetwork.py`:
  - `build_init_packet()`: Sestavuje iniciační paket `DH_INIT` pro zahájení výměny.
  - `process_init_packet()` & `process_accept_packet()`: Zpracovávají handshake a provádějí finální výpočet klíče.

**Průběh v aplikaci:**
- klient
    - po výměně RSA klíčů použít příkaz ``dh`` (v režimu ``--unsecure`` rovnou)
    - v bezpečném režimu jsou ``DH_INIT`` i ``DH_ACCEPT`` podepsány RSA klíčem odesílatele; klient odmítne nepodepsaný ``DH_ACCEPT``
    - při úspěchu je následující komunikace šifrována pomocí AES-GCM

### AES-GCM
- klient
    - po úspěšném ``dh`` vznikne symetrický AES session key
    - při odeslání zprávy: vygeneruje se náhodný nonce -> zpráva se zašifruje -> vznikne paket ``length | nonce | tag | ciphertext``
    - při přijetí zprávy: ověří se autentizační tag; pokud ověření selže, zpráva se zahodí, jinak se zobrazí
- server
    - po úspěšném DH uchovává AES klíč pro každého klienta zvlášť a po jeho odpojení ho zahodí
    - zprávu od klienta dešifruje jeho klíčem, vytvoří zprávu ve tvaru ``port: zpráva`` a každému dalšímu klientovi ji zašifruje jeho klíčem

### Chatování
- klient
    - libovolný jiný text se odešle jako zpráva do chatu
    - bez session klíče se v bezpečném režimu zpráva **neodešle**; v režimu ``--unsecure`` se odešle nešifrovaně
    - server zprávu dešifruje a přepošle ostatním připojeným klientům
- útočník (pokud klienti komunikují přes něj)
    - ``attack`` - zapne/vypne aktivní MITM útok: útočník zachytí DH výměnu, podvrhne vlastní veřejné klíče, vyjedná si šifrování s oběma stranami a pak dešifruje a vypisuje celou komunikaci
        - útok **uspěje pouze v režimu ``--unsecure``**; v bezpečném režimu podpis prozradí změněný ``DH_INIT``, server paket zahodí a klíč se nevyjedná
    - ``tamper <text>`` - nahradí obsah další zachycené a dešifrované zprávy zadaným textem a znovu ji zašifruje
    - ``spoof`` - zapne/vypne nahrazování všech zpráv falešnými zprávami na obě strany
    - ``help`` - vypíše seznam příkazů

### Ukončení
- server
    - kombinací Ctrl + C
- klient, útočník
    - příkazem ``exit`` nebo kombinací Ctrl + C

### Struktura projektu
- ``main.py`` - parametry příkazové řádky a spuštění zvolené role
- ``client.py``, ``server.py``, ``attacker.py`` - jednotlivé role; ``networkservice.py`` - společný základ a AES-GCM pakety
- ``protocol.py`` - formáty všech paketů
- ``networkstack.py`` - TCP vrstva s rámci s 4-bajtovou délkou
- ``RSA/``, ``diffieHellman/``, ``GCM/`` - kryptografické moduly
- ``Test/`` - unit a end-to-end testy
