# PuccioQuiz (Quiz + Ruota premi)

Questo progetto è composto da:
- **Frontend statico**: `test.html` (quiz), `ruota.html` (ruota), `perso.html` (esito negativo), `GDPR.html` (privacy).
- **Backend Node/Express**: `server/index.js` (API + hosting delle pagine).

## Requisiti
- Node.js **18+**
- (Opzionale ma consigliato) un progetto **Supabase** per salvare in modo persistente le partecipazioni.

## Avvio rapido (locale)
1. Copia la configurazione:
   - Duplica `.env.example` in `.env`
2. Installa dipendenze:
   - `npm install`
3. Avvia il server:
   - `npm start`
4. Apri il quiz:
   - `http://127.0.0.1:3000/test.html`

> Nota: il backend serve anche le pagine HTML, così quiz e API stanno sulla **stessa porta**.

## Configurare Supabase (persistenza + email cifrata)
Il backend salva:
- `email_fingerprint` (HMAC SHA-256 con pepper) per cercare l’utente senza email in chiaro
- email cifrata **AES-256-GCM** (solo lato server, mai nel browser)

### 1) Crea la tabella
Nel tuo progetto Supabase, apri **SQL Editor** ed esegui:
- `supabase/schema.sql`

### 2) Compila il `.env`
Nel file `.env` imposta:
- `SUPABASE_URL`
- `SUPABASE_SERVICE_ROLE_KEY` (**solo backend, non pubblicarla**)
- `EMAIL_ENCRYPTION_KEY` (64 caratteri hex)
- `EMAIL_FINGERPRINT_PEPPER` (minimo 16 caratteri)
- `PRIZE_VALIDITY_DAYS` (es. 90)

Per generare `EMAIL_ENCRYPTION_KEY`:
```bash
node -e "console.log(require('crypto').randomBytes(32).toString('hex'))"
```

## API disponibili
- `GET /api/health`
- `POST /api/quiz-finish` `{ email, testPassed, q10Values }`
- `POST /api/participation-state` `{ email }`
- `POST /api/spin-result` `{ email, prizeName }`

## Note importanti
- **Non aprire le pagine come file** (es. `file:///.../test.html`) se vuoi usare le API: aprile dal server (`http://127.0.0.1:3000/...`).
- Se Supabase **non** è configurato, il backend usa un **fallback in-memory** (i dati si perdono al riavvio).

## Uscita / fine gioco (pulsante “Esci”)
Per evitare problemi con `window.close()` (spesso bloccato dai browser), la ruota porta l’utente su `fine.html` e prova a chiudere; se non può, fa redirect a un URL configurabile.

In `ruota.html` puoi impostare:
```html
<meta name="puccio-exit-url" content="about:blank" />
```
Puoi sostituire `about:blank` con un tuo URL (es. sito principale) per uscire in modo controllato.
