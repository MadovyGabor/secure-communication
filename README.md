# Zabezpečená komunikace
- autoři: Gabriel Madový (283573), Petr Věříš (283559), Oliver Synak (281728), Donát Szabó (283384)

## Popis
- jednoduchý chatovací program
- k serveru se připojí klienti a mohou chatovat ve skupině

## Návod
### Spuštění a připojení
- server
    - ``python main.py server [adresa ze které bude přijímat přopojení] [port] [jméno instance]``
    - př. ``python main.py server 127.0.0.1 12345 skveleuzivatelskejmeno``
- klient
    - ``python main.py client [adresa serveru] [port]``

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

### Diffie-Hellman
- klient
    - po úspěšné výměně klíčů použít příkaz ``dh``
    - při úspěchu bude následující komunikace zašifrována pomocí AES-GCM

### Chatování
- klient
    - odeslané zprávy se přeposílají zbytku připojených klientů

### Ukončení
- server
    - kombinací Ctrl + C :)
- klient
    - příkazem ``exit``