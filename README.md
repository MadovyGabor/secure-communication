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

### Diffie-Hellman
- klient
    - po úspěšné výměně klíčů použít příkaz ``dh``
    - při úspěchu bude následující komunikace zašifrována pomocí AES-GCM
- útočník
    - vymění se klíče jak s klientem, tak se serverem
    - při úspěchu může odposlouchávat komunikaci mezi klientem a serverem

### AES-GCM
- klient
    -  po úspěšné výměně klíčů pomocí příkazu ``dh`` se vytvoří symetrický AES session key
    - všechny následující zprávy se odesílají šifrované pomocí AES-GCM
    - při odeslání zprávy:
        - vygeneruje se náhodný nonce -> zpráva se zašifruje -> vytvoří se packet ve tvaru: ``length | nonce | tag | ciphertext``
    - při přijetí zprávy:
        - zpráva se dešifruje pomocí AES klíče -> ověří se autentizační tag - > pokud ověření selže, zpráva se zahodí / pokud je validní, zobrazí se uživateli
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
