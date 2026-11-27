"use strict";
/*
 * Firma SSHSIG nel browser per chiavi OpenSSH NON protette da passphrase:
 *   - ssh-ed25519
 *   - ssh-rsa (firma rsa-sha2-512, come `ssh-keygen -Y sign`)
 *   - ecdsa-sha2-nistp256 (firma con SHA-256, come `ssh-keygen -Y sign`)
 * Il file della chiave viene letto dal browser, la firma è calcolata qui e
 * la chiave privata non viene inviata a nessuno.
 *
 * Il formato della firma è quello di PROTOCOL.sshsig, quindi il server la
 * verifica con `ssh-keygen -Y verify`.
 */
const SSHSign = (function () {
  const enc = new TextEncoder();
  const dec = new TextDecoder();

  function concat(...parts) {
    const total = parts.reduce((n, p) => n + p.length, 0);
    const out = new Uint8Array(total);
    let off = 0;
    for (const p of parts) { out.set(p, off); off += p.length; }
    return out;
  }

  function u32(n) {
    const b = new Uint8Array(4);
    new DataView(b.buffer).setUint32(0, n);
    return b;
  }

  // Stringa SSH: lunghezza (4 byte, big-endian) seguita dai byte
  function sshString(data) {
    const b = typeof data === "string" ? enc.encode(data) : data;
    return concat(u32(b.length), b);
  }

  // mpint SSH di un intero senza segno (big-endian): niente zeri iniziali, zero di padding se il bit alto è 1
  function sshMpint(bytes) {
    let i = 0;
    while (i < bytes.length - 1 && bytes[i] === 0) i++;
    const v = bytes.subarray(i);
    const pad = v.length && (v[0] & 0x80) ? 1 : 0;
    const out = new Uint8Array(pad + v.length);
    out.set(v, pad);
    return sshString(out);
  }

  function b64decode(s) {
    return Uint8Array.from(atob(s), c => c.charCodeAt(0));
  }

  function b64encode(bytes) {
    let s = "";
    for (const x of bytes) s += String.fromCharCode(x);
    return btoa(s);
  }

  function b64url(bytes) {
    return b64encode(bytes).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
  }

  // Intero grande (mpint SSH, big-endian) <-> BigInt
  function bigFromBytes(bytes) {
    if (!bytes.length) return 0n;
    return BigInt("0x" + Array.from(bytes, b => b.toString(16).padStart(2, "0")).join(""));
  }

  function bytesFromBig(n) {
    let hex = n.toString(16);
    if (hex.length % 2) hex = "0" + hex;
    const out = new Uint8Array(hex.length / 2);
    for (let i = 0; i < out.length; i++) out[i] = parseInt(hex.substr(i * 2, 2), 16);
    return out;
  }

  function modInverse(a, m) {
    let [oldR, r] = [a % m, m];
    let [oldS, s] = [1n, 0n];
    while (r !== 0n) {
      const q = oldR / r;
      [oldR, r] = [r, oldR - q * r];
      [oldS, s] = [s, oldS - q * s];
    }
    return ((oldS % m) + m) % m;
  }

  function reader(buf) {
    let off = 0;
    const need = n => {
      if (off + n > buf.length) throw new Error("Formato della chiave non valido");
    };
    return {
      u32() {
        need(4);
        const v = new DataView(buf.buffer, buf.byteOffset + off, 4).getUint32(0);
        off += 4;
        return v;
      },
      bytes(n) {
        need(n);
        const v = buf.subarray(off, off + n);
        off += n;
        return v;
      },
      string() {
        return this.bytes(this.u32());
      },
    };
  }

  /* Legge una chiave privata OpenSSH ("openssh-key-v1") non protetta da passphrase. */
  function parseOpenSSHKey(text) {
    const m = /-----BEGIN OPENSSH PRIVATE KEY-----([\s\S]+?)-----END OPENSSH PRIVATE KEY-----/.exec(text);
    if (!m) throw new Error("Il file non è una chiave privata OpenSSH");

    const data = b64decode(m[1].replace(/\s+/g, ""));
    const magic = "openssh-key-v1\0";
    if (dec.decode(data.subarray(0, magic.length)) !== magic) {
      throw new Error("Formato della chiave non riconosciuto");
    }

    const r = reader(data.subarray(magic.length));
    const cipher = dec.decode(r.string());
    r.string(); // kdfname
    r.string(); // kdfoptions
    if (cipher !== "none") {
      const err = new Error("Chiave protetta da passphrase");
      err.code = "PASSPHRASE";
      throw err;
    }
    if (r.u32() !== 1) throw new Error("File con più chiavi non supportato");
    const pubBlob = new Uint8Array(r.string());

    const p = reader(r.string());
    const check1 = p.u32();
    const check2 = p.u32();
    if (check1 !== check2) throw new Error("File della chiave danneggiato");

    const keyType = dec.decode(p.string());

    if (keyType === "ssh-ed25519") {
      p.string();                              // chiave pubblica (già in pubBlob)
      const secret = p.string();               // 64 byte: seed (32) + chiave pubblica (32)
      const comment = dec.decode(p.string());
      return { type: "ed25519", pubBlob, seed: new Uint8Array(secret.subarray(0, 32)), comment };
    }

    if (keyType === "ssh-rsa") {
      const n = bigFromBytes(p.string());
      const e = bigFromBytes(p.string());
      const d = bigFromBytes(p.string());
      const iqmp = bigFromBytes(p.string());
      const pr = bigFromBytes(p.string());     // p
      const q = bigFromBytes(p.string());      // q
      const comment = dec.decode(p.string());
      const jwk = {
        kty: "RSA",
        n: b64url(bytesFromBig(n)),
        e: b64url(bytesFromBig(e)),
        d: b64url(bytesFromBig(d)),
        p: b64url(bytesFromBig(pr)),
        q: b64url(bytesFromBig(q)),
        dp: b64url(bytesFromBig(d % (pr - 1n))),
        dq: b64url(bytesFromBig(d % (q - 1n))),
        qi: b64url(bytesFromBig(iqmp || modInverse(q, pr))),
        ext: true,
      };
      return { type: "rsa", pubBlob, jwk, comment };
    }

    if (keyType === "ecdsa-sha2-nistp256") {
      const curve = dec.decode(p.string());
      const q = new Uint8Array(p.string());    // punto pubblico: 0x04 || X (32) || Y (32)
      const d = p.string();                    // scalare privato (mpint)
      const comment = dec.decode(p.string());
      if (curve !== "nistp256" || q.length !== 65 || q[0] !== 4) {
        throw new Error("Chiave ECDSA non supportata: solo nistp256");
      }
      const dBytes = new Uint8Array(32);       // mpint: zeri iniziali da togliere, poi allineare a 32 byte
      const dTrim = d.length > 32 ? d.subarray(d.length - 32) : d;
      dBytes.set(dTrim, 32 - dTrim.length);
      const jwk = {
        kty: "EC",
        crv: "P-256",
        x: b64url(q.subarray(1, 33)),
        y: b64url(q.subarray(33, 65)),
        d: b64url(dBytes),
        ext: true,
      };
      return { type: "ecdsa", pubBlob, jwk, comment };
    }

    throw new Error(`Tipo di chiave non supportato nel browser: ${keyType}`);
  }

  // Intestazione PKCS#8 per una chiave privata Ed25519
  const PKCS8_PREFIX = new Uint8Array([
    0x30, 0x2e, 0x02, 0x01, 0x00, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x04, 0x22, 0x04, 0x20,
  ]);

  // Crea la chiave di firma WebCrypto dalla chiave letta
  async function importSigner(parsed) {
    try {
      if (parsed.type === "ed25519") {
        return await crypto.subtle.importKey(
          "pkcs8", concat(PKCS8_PREFIX, parsed.seed), { name: "Ed25519" }, false, ["sign"]
        );
      }
      if (parsed.type === "ecdsa") {
        return await crypto.subtle.importKey(
          "jwk", parsed.jwk, { name: "ECDSA", namedCurve: "P-256" }, false, ["sign"]
        );
      }
      return await crypto.subtle.importKey(
        "jwk", parsed.jwk, { name: "RSASSA-PKCS1-v1_5", hash: "SHA-512" }, false, ["sign"]
      );
    } catch {
      throw new Error("Questo browser non riesce a usare questa chiave: prova con Chrome o Firefox aggiornati, oppure usa la sezione con il terminale");
    }
  }

  /* Produce il testo "-----BEGIN SSH SIGNATURE-----" per il nonce dato. */
  async function signNonce(key, parsed, nonce, namespace) {
    const hash = new Uint8Array(await crypto.subtle.digest("SHA-512", enc.encode(nonce)));
    const signedData = concat(
      enc.encode("SSHSIG"),
      sshString(namespace),
      sshString(""),          // reserved
      sshString("sha512"),
      sshString(hash)
    );

    let sigAlg, sig;
    if (parsed.type === "ed25519") {
      sigAlg = "ssh-ed25519";
      sig = new Uint8Array(await crypto.subtle.sign({ name: "Ed25519" }, key, signedData));
    } else if (parsed.type === "ecdsa") {
      // Come OpenSSH: ECDSA P-256 firma il messaggio con SHA-256.
      // WebCrypto dà r||s (32+32 byte); SSH li vuole come due mpint dentro una stringa.
      sigAlg = "ecdsa-sha2-nistp256";
      const raw = new Uint8Array(await crypto.subtle.sign({ name: "ECDSA", hash: "SHA-256" }, key, signedData));
      sig = concat(sshMpint(raw.subarray(0, 32)), sshMpint(raw.subarray(32, 64)));
    } else {
      sigAlg = "rsa-sha2-512";
      sig = new Uint8Array(await crypto.subtle.sign({ name: "RSASSA-PKCS1-v1_5" }, key, signedData));
    }
    const sigBlob = concat(sshString(sigAlg), sshString(sig));

    const blob = concat(
      enc.encode("SSHSIG"),
      u32(1),
      sshString(parsed.pubBlob),
      sshString(namespace),
      sshString(""),
      sshString("sha512"),
      sshString(sigBlob)
    );
    const body = b64encode(blob).match(/.{1,70}/g).join("\n");
    return `-----BEGIN SSH SIGNATURE-----\n${body}\n-----END SSH SIGNATURE-----\n`;
  }

  return { parseOpenSSHKey, importSigner, signNonce };
})();

if (typeof module !== "undefined" && module.exports) module.exports = SSHSign;
