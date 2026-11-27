# Keyring con accesso via chiave SSH

Web app per un keyring condiviso. Ogni utente accede firmando una sfida con la propria chiave SSH privata, che non viene mai inviata al server. Ogni chiave ha un ruolo:

- **read**: può consultare le voci.
- **write**: può consultare, creare, modificare ed eliminare le voci.

Il server usa solo Node.js (nessuna dipendenza esterna) e `ssh-keygen` di OpenSSH per verificare le firme. Le voci sono cifrate a riposo con AES-256-GCM.

## Requisiti

- Node.js 18 o superiore
- OpenSSH 8.2 o superiore sul server (per `ssh-keygen -Y`)
- OpenSSH sul computer client

## Installazione

1. Genera la chiave master di cifratura del keyring (conservala in un password manager o in un secret store):

   ```bash
   node -e "console.log(require('crypto').randomBytes(32).toString('base64'))"
   ```

2. Configura gli utenti in `config/access.json`. Per ogni utente indica la **chiave pubblica** (il contenuto del file `.pub`, mai la privata), il ruolo e il perimetro di voci:

   ```json
   {
     "users": [
       { "name": "alice", "publicKey": "ssh-ed25519 AAAA... alice@laptop", "role": "write", "entries": ".*" },
       { "name": "carla", "publicKey": "ssh-rsa AAAA... carla@desktop",    "role": "write", "entries": "^prod-" },
       { "name": "bob",   "publicKey": "ssh-ed25519 AAAA... bob@desktop",  "role": "read",  "entries": "^(web|api)-" }
     ]
   }
   ```

   - `name`: da 1 a 64 caratteri tra lettere (anche accentate), cifre, spazi, `.`, `_`, `'` e `-`. Niente spazi iniziali o finali. Il nome è unico e appare nelle sessioni e nell'audit log.
   - `role`: `read` (solo lettura) oppure `write` (lettura e scrittura).
   - `entries` (facoltativo, default `".*"`): **regex applicata al nome della voce**. Decide quali voci l'utente vede e può modificare.

3. Avvia il server:

   ```bash
   export KEYRING_KEY="<valore generato al punto 1>"
   export HOST=127.0.0.1   # opzionale, default 127.0.0.1
   export PORT=8080        # opzionale
   npm start
   ```

   Apri `http://127.0.0.1:8080`.

   Per mettere il server in rete, usalo solo dietro HTTPS con un reverse proxy (Caddy, nginx, Traefik), poi imposta `COOKIE_SECURE=1`.

## Come accedere

1. Nella pagina clicca **Scegli file chiave privata** e seleziona il file della tua chiave (per esempio `~/.ssh/id_ed25519`).
2. Il browser legge la chiave, firma la sfida e accede. Non serve altro.

La chiave non viene caricata sul server: la firma avviene nel browser e il server riceve solo la firma.

**Limiti della firma nel browser:**
- Funziona con chiavi **ed25519**, **RSA** (almeno 2048 bit) ed **ECDSA nistp256** senza passphrase, e con browser recenti (Chrome 137+, Firefox 129+, Safari 17+ per Ed25519; RSA ed ECDSA funzionano anche su versioni precedenti).
- Per chiavi con passphrase, la pagina apre la sezione **Chiave con passphrase**: lì copi un comando da eseguire nel terminale (macOS, Linux, WSL o Git Bash), poi incolli l'output.

La sfida scade dopo 2 minuti ed è monouso. Se il login fallisce, scegli di nuovo il file.

## Esecuzione come servizio (systemd)

Il servizio gira come utente `admin`, direttamente dalla cartella del progetto (`/home/admin/ssh-keyring`), senza copie in `/opt`.

La cartella `deploy/` contiene:

- `ssh-keyring.service`: template della unit. `install.sh` sostituisce utente, cartella, Node.js e cartella SSH.
- `keyring.env.example`: modello della configurazione (`KEYRING_KEY`, `HOST`, `PORT`, `COOKIE_SECURE`).
- `install.sh`: genera la unit, crea la configurazione e avvia il servizio.

Installazione, dalla cartella del progetto:

```bash
cd /home/admin/ssh-keyring
sudo ./deploy/install.sh
```

Lo script:
1. verifica che `admin` possa leggere il codice e scrivere in `data/`;
2. trova Node.js nella shell di login di `admin` (quindi anche con nvm) e controlla che sia la versione 18 o superiore;
3. crea `/etc/ssh-keyring/keyring.env` con una nuova `KEYRING_KEY`, se il file non esiste;
4. genera `/etc/systemd/system/ssh-keyring.service`, abilita e riavvia il servizio.

Parametri facoltativi:

```bash
sudo SERVICE_USER=admin NODE_BIN=/home/admin/.nvm/versions/node/v20.19.5/bin/node ./deploy/install.sh
```

Comandi utili:

```bash
systemctl status ssh-keyring
journalctl -u ssh-keyring -f
sudo systemctl restart ssh-keyring   # dopo modifiche a config/access.json
```

Protezioni applicate alla unit, con utente `admin`:
- `ProtectHome=read-only`: l'app non può modificare la home. Serve questa impostazione per usare Node.js installato con nvm.
- `InaccessiblePaths=/home/admin/.ssh`: le chiavi SSH di `admin` non sono visibili all'app.
- `ReadWritePaths=/home/admin/ssh-keyring/data`: unico percorso scrivibile, con voci cifrate e audit log.
- File system di sola lettura, `/tmp` privato, nessuna capability, `NoNewPrivileges`, filtro delle system call.

Attenzione: il processo gira con l'identità di `admin`. Se l'app venisse compromessa, un attaccante avrebbe accesso a tutto ciò che `admin` può leggere, a parte `~/.ssh`. Per questo conviene un utente dedicato, ma così hai scelto di usare `admin`.

Configurazione: `/etc/ssh-keyring/keyring.env` (root, gruppo `admin`, permessi `640`). Contiene la chiave master: fanne un backup sicuro.

Il servizio ascolta su `127.0.0.1:8080`. Per l'accesso dall'esterno usa un reverse proxy HTTPS (Caddy, nginx) e lascia `COOKIE_SECURE=1`.

Se una versione precedente era installata in `/opt/ssh-keyring` con l'utente `keyring`, puoi rimuoverla:

```bash
sudo systemctl disable --now ssh-keyring   # solo se ancora attiva con la vecchia unit
sudo rm -rf /opt/ssh-keyring
sudo userdel keyring 2>/dev/null || true
```

## Pubblicazione su un sottopercorso (nginx)

Per servire Keyring come `https://tuo-host/keyring/`, usa un reverse proxy che **rimuove il prefisso** `/keyring/` prima di inoltrare la richiesta al servizio. Il frontend usa URL relativi, quindi funziona da qualsiasi sottopercorso.

```nginx
location = /keyring { return 301 /keyring/; }

location /keyring/ {
    proxy_pass http://127.0.0.1:8080/;   # lo slash finale rimuove /keyring/
    proxy_http_version 1.1;
    proxy_set_header Host $host;
    proxy_set_header X-Real-IP $remote_addr;
    proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
    proxy_set_header X-Forwarded-Proto $scheme;
}
```

Senza lo slash finale in `proxy_pass`, nginx inoltra `/keyring/...` così com'è e l'app risponde 404. Con HTTPS imposta `COOKIE_SECURE=1` in `/etc/ssh-keyring/keyring.env`.

## Voci gerarchiche (cartelle)

Il nome di una voce può contenere `/` per organizzarla in cartelle, per esempio `prod/db/main`. Le cartelle sono implicite: esistono finché contengono almeno una voce.

Regole sui percorsi:
- fino a 8 livelli e 200 caratteri in totale;
- ogni segmento non può essere vuoto, né `.` o `..`, né avere spazi attorno (`prod / db` non è valido, `Mario Rossi` sì);
- niente `/` iniziale o finale, niente caratteri di controllo.

Nell'interfaccia le voci sono mostrate ad albero, con cartelle apribili e chiudibili. Con la ricerca attiva la lista diventa piatta e mostra i percorsi completi.

Operazioni sulle cartelle (solo ruolo `write`):
- **Rinomina** (`POST /api/folders/rename` con `from` e `to`): sposta tutte le voci sotto la cartella. Se una sola voce finirebbe fuori dal perimetro, l'operazione viene rifiutata e non cambia nulla. Non si può spostare una cartella dentro sé stessa.
- **Elimina** (`POST /api/folders/delete` con `path`): elimina le voci della cartella, ma solo quelle nel perimetro dell'utente.

Il perimetro regex lavora sul percorso completo, quindi `"entries": "^prod/"` limita un utente al sottoalbero `prod`. Le cartelle non sono oggetti separati: non hanno permessi propri.

Nota: i nomi non devono essere unici. Più voci possono avere lo stesso percorso.

## Perimetro di accesso per nome (regex)

Il campo `entries` limita l'utente alle voci il cui **nome** corrisponde alla regex. Il controllo è fatto dal server su ogni richiesta.

| Operazione | Regola |
|---|---|
| Elenco | mostra solo le voci nel perimetro |
| Creazione | il nome deve rientrare nel perimetro, altrimenti 403 |
| Modifica | la voce deve essere nel perimetro (altrimenti 404) e il nuovo nome deve restare nel perimetro (altrimenti 403) |
| Eliminazione | solo voci nel perimetro (altrimenti 404) |

Le voci fuori perimetro non vengono mai inviate al browser dell'utente e non si possono rilevare: una voce nascosta risponde come una voce inesistente.

Esempi di regex:

- `.*`: tutte le voci.
- `^prod-`: nomi che iniziano per `prod-`.
- `^(web|api)-`: nomi che iniziano per `web-` oppure `api-`.
- `-db$`: nomi che finiscono con `-db`.

Note:
- La regex è **case-insensitive**: `^prod-` corrisponde anche a `Prod-Db`.
- La sintassi è quella di JavaScript (`RegExp`). Una regex non valida blocca l'avvio del server con un messaggio chiaro.
- Il perimetro vale solo per il nome: le note e lo username non influiscono.
- Scegli regex semplici: il server le applica a ogni richiesta e un pattern complesso su nomi lunghi può rallentarle.

## Come funziona la verifica

- Il server genera un nonce casuale a 256 bit e lo ricorda per 2 minuti.
- `ssh-keygen -Y find-principals` individua l'utente la cui chiave ha prodotto la firma, usando `access.json`.
- `ssh-keygen -Y verify` controlla che la firma copra esattamente quel nonce, nel dominio `keyring-login`. Una firma fatta per altri scopi non viene accettata.
- Il ruolo dell'utente viene letto da `access.json` e salvato nella sessione. Le sessioni durano 30 minuti dall'ultima attività.

## Struttura

```
ssh-keyring/
├── server.js           # backend: sfide, verifica firma, sessioni, API, archivio cifrato
├── config/access.json  # utenti, chiavi pubbliche e ruoli
├── public/
│   ├── index.html
│   ├── app.js          # login, lista voci, editor
│   ├── sshsign.js      # lettura chiave OpenSSH e firma SSHSIG nel browser
│   └── style.css
├── data/
│   ├── keyring.enc     # voci cifrate (creato al primo salvataggio)
│   └── audit.log       # accessi e modifiche, senza valori dei segreti
├── deploy/
│   ├── ssh-keyring.service
│   ├── keyring.env.example
│   └── install.sh
└── package.json
```

## API

| Metodo | Percorso | Ruolo | Descrizione |
|---|---|---|---|
| GET | `/api/challenge` | pubblico | nuova sfida |
| POST | `/api/login` | pubblico | `{nonce, signature}` → cookie di sessione |
| POST | `/api/logout` | sessione | termina la sessione |
| GET | `/api/me` | read/write | utente, ruolo e perimetro |
| GET | `/api/entries` | read/write | elenco voci |
| POST | `/api/entries` | write | crea voce |
| PUT | `/api/entries/:id` | write | modifica voce |
| DELETE | `/api/entries/:id` | write | elimina voce |

## Note di sicurezza

- Le chiavi private restano sul computer dell'utente. Il server riceve solo la firma.
- Ruolo e perimetro vengono applicati lato server su ogni richiesta, non solo nell'interfaccia.
- Il cookie di sessione è `HttpOnly` e `SameSite=Strict`. Le scritture accettano solo `application/json`.
- Le voci sono cifrate con AES-256-GCM. Se perdi `KEYRING_KEY`, i dati non sono recuperabili.
- L'audit log registra accessi e modifiche (utente, azione, id), ma non i segreti.

## Limitazioni note

- Le sessioni e le sfide sono in memoria: un riavvio disconnette tutti gli utenti.
- Non c'è un limite di tentativi di login per IP. Metti il servizio dietro un reverse proxy che applichi rate limiting.
- Un solo processo: non adatto a più istanze in parallelo senza uno storage condiviso.
- Il ruolo viene letto da `access.json` all'avvio. Dopo una modifica, riavvia il server.
- Per revocare un accesso, rimuovi l'utente da `access.json` e riavvia. Per restringere un utente, modifica il suo `entries`.
