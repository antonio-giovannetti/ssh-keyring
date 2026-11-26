#!/usr/bin/env bash
# Installa Keyring come servizio systemd che gira come utente indicato,
# direttamente dalla cartella del progetto (nessuna copia in /opt).
#
# Uso (dalla cartella del progetto):
#   sudo ./deploy/install.sh
#   sudo SERVICE_USER=admin NODE_BIN=/percorso/node ./deploy/install.sh   # opzionale
set -euo pipefail

SERVICE_USER="${SERVICE_USER:-admin}"
APP_DIR="$(cd "$(dirname "$0")/.." && pwd)"
ENV_DIR=/etc/ssh-keyring
UNIT=/etc/systemd/system/ssh-keyring.service

[[ $EUID -eq 0 ]] || { echo "Esegui con sudo." >&2; exit 1; }
id "$SERVICE_USER" >/dev/null 2>&1 || { echo "Utente $SERVICE_USER non esistente." >&2; exit 1; }
USER_HOME="$(getent passwd "$SERVICE_USER" | cut -d: -f6)"

# Il servizio deve poter leggere il codice e scrivere nella cartella data
sudo -u "$SERVICE_USER" test -r "$APP_DIR/server.js" \
  || { echo "$SERVICE_USER non può leggere $APP_DIR/server.js" >&2; exit 1; }
sudo -u "$SERVICE_USER" test -w "$APP_DIR" \
  || { echo "$SERVICE_USER non può scrivere in $APP_DIR (serve per data/)" >&2; exit 1; }

# Node.js: cerca il binario nella shell di login dell'utente (così trova anche nvm)
NODE_BIN="${NODE_BIN:-$(sudo -u "$SERVICE_USER" bash -lc 'command -v node' 2>/dev/null || true)}"
[[ -n "$NODE_BIN" ]] || { echo "Node.js non trovato per $SERVICE_USER (serve >= 18). Indica NODE_BIN=..." >&2; exit 1; }
NODE_BIN="$(readlink -f "$NODE_BIN")"
sudo -u "$SERVICE_USER" test -x "$NODE_BIN" \
  || { echo "$SERVICE_USER non può eseguire $NODE_BIN" >&2; exit 1; }
sudo -u "$SERVICE_USER" "$NODE_BIN" -e 'process.exit(Number(process.versions.node.split(".")[0]) >= 18 ? 0 : 1)' \
  || { echo "Serve Node.js >= 18 (trovato: $(sudo -u "$SERVICE_USER" "$NODE_BIN" -v))." >&2; exit 1; }
echo "Node.js: $NODE_BIN ($(sudo -u "$SERVICE_USER" "$NODE_BIN" -v))"

# Dati cifrati e audit log: scrivibili dall'utente del servizio
install -d -m 750 -o "$SERVICE_USER" -g "$SERVICE_USER" "$APP_DIR/data"

# Configurazione: root scrive, l'utente del servizio legge
install -d -m 750 -o root -g "$SERVICE_USER" "$ENV_DIR"
if [[ ! -f "$ENV_DIR/keyring.env" ]]; then
  install -m 640 -o root -g "$SERVICE_USER" "$APP_DIR/deploy/keyring.env.example" "$ENV_DIR/keyring.env"
  KEY=$(sudo -u "$SERVICE_USER" "$NODE_BIN" -e "console.log(require('crypto').randomBytes(32).toString('base64'))")
  sed -i "s|^KEYRING_KEY=.*|KEYRING_KEY=${KEY}|" "$ENV_DIR/keyring.env"
  echo "Creato $ENV_DIR/keyring.env con una nuova KEYRING_KEY. Salvala in un luogo sicuro."
else
  chown root:"$SERVICE_USER" "$ENV_DIR/keyring.env"
  chmod 640 "$ENV_DIR/keyring.env"
  echo "$ENV_DIR/keyring.env esiste già: chiave non modificata, permessi aggiornati."
fi

# Unit generata con utente, cartella, Node e cartella SSH reali
sed -e "s|@USER@|${SERVICE_USER}|g" \
    -e "s|@APP_DIR@|${APP_DIR}|g" \
    -e "s|@NODE_BIN@|${NODE_BIN}|g" \
    -e "s|@SSH_DIR@|${USER_HOME}/.ssh|g" \
    "$APP_DIR/deploy/ssh-keyring.service" > "$UNIT"
chmod 644 "$UNIT"
if command -v systemd-analyze >/dev/null; then
  systemd-analyze verify "$UNIT" 2>&1 | grep -v "^$" || true
fi

systemctl daemon-reload
systemctl enable ssh-keyring.service
systemctl restart ssh-keyring.service

echo
systemctl --no-pager --lines=5 status ssh-keyring.service || true
echo
echo "Log:       journalctl -u ssh-keyring -f"
echo "Ricarica:  sudo systemctl restart ssh-keyring   (dopo modifiche a config/access.json)"
