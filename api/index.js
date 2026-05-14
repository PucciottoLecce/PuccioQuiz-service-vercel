/* PuccioQuiz backend (Express + Supabase + Resend)
   HARDENING 2026-05:
   - Rate limiting (in-memory) per IP + per email per ridurre abuso/enumeration
   - Non fidarsi di testPassed dal client: calcolo lato server (richiede answers dal frontend)
   - Risposta "già partecipato" user-friendly (senza errore finto di connessione)
   - trust proxy per Render (x-forwarded-for)
   - Header di sicurezza di base (senza dipendenze extra)
*/

const path = require("path");
const crypto = require("crypto");

const express = require("express");
const cors = require("cors");
require("dotenv").config();

const { createClient } = require("@supabase/supabase-js");

const PORT = Number(process.env.PORT || 3000);
const PRIZE_VALIDITY_DAYS = Number(process.env.PRIZE_VALIDITY_DAYS || 90);

const SUPABASE_URL = (process.env.SUPABASE_URL || "").trim();
const SUPABASE_SERVICE_ROLE_KEY = (process.env.SUPABASE_SERVICE_ROLE_KEY || "").trim();

const EMAIL_FINGERPRINT_PEPPER = (process.env.EMAIL_FINGERPRINT_PEPPER || "").trim();

const RESEND_API_KEY = (process.env.RESEND_API_KEY || "").trim();
const FROM_EMAIL = (process.env.FROM_EMAIL || "").trim();

// Se vuoi supportare vecchi client che mandano solo testPassed (sconsigliato), imposta a "true".
const ALLOW_LEGACY_TESTPASSED = String(process.env.ALLOW_LEGACY_TESTPASSED || "").trim().toLowerCase() === "true";

// Rate limit (valori conservativi, modificabili via env)
const RL_WINDOW_MS = Number(process.env.RATE_LIMIT_WINDOW_MS || 10 * 60 * 1000); // 10 min
const RL_MAX_PER_IP = Number(process.env.RATE_LIMIT_MAX_PER_IP || 120); // 120 req/10min per IP
const RL_MAX_QUIZ_FINISH_PER_EMAIL = Number(process.env.RATE_LIMIT_MAX_QUIZ_FINISH_PER_EMAIL || 6); // 6/10min per email
const RL_MAX_SPIN_PER_EMAIL = Number(process.env.RATE_LIMIT_MAX_SPIN_PER_EMAIL || 6); // 6/10min per email

function normalizeEmail(email) {
  return String(email || "").trim().toLowerCase();
}

function escapeHtml(s) {
  return String(s)
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#039;");
}

function requireEnv(name, value) {
  if (!value) throw new Error(`Missing env var: ${name}`);
}

function isValidEmail(email) {
  const e = normalizeEmail(email);
  return e.length >= 5 && e.length <= 254 && e.includes("@");
}

function emailFingerprint(email) {
  requireEnv("EMAIL_FINGERPRINT_PEPPER", EMAIL_FINGERPRINT_PEPPER);
  return crypto.createHmac("sha256", EMAIL_FINGERPRINT_PEPPER).update(normalizeEmail(email)).digest("hex");
}

function makeToken() {
  const alphabet = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789"; // evita 0/O/1/I
  const bytes = crypto.randomBytes(8);
  let out = "";
  for (let i = 0; i < bytes.length; i++) out += alphabet[bytes[i] % alphabet.length];
  return out;
}

function validUntilIso(days) {
  const d = new Date();
  d.setDate(d.getDate() + days);
  return d.toISOString();
}

function okJson(res, payload) {
  res.setHeader("Cache-Control", "no-store");
  res.json(payload);
}

function getClientIp(req) {
  // con trust proxy impostato, Express usa X-Forwarded-For per req.ip
  const ip = (req.ip || "").trim();
  if (ip) return ip;
  const xf = (req.headers["x-forwarded-for"] || "").toString().split(",")[0].trim();
  return xf || "unknown";
}

function supabaseFriendlyError(err) {
  if (err && err.code === "PGRST125") {
    return (
      "Supabase: URL non valido (PGRST125). Verifica che SUPABASE_URL sia ESATTAMENTE il \"Project URL\" " +
      "(tipo https://xxxx.supabase.co) e NON includa /rest/v1, /auth/v1 o altri path."
    );
  }

  if (
    err &&
    (err.code === "PGRST205" ||
      (typeof err.message === "string" && err.message.includes("schema cache") && err.message.includes("quiz_entries")))
  ) {
    return "Supabase non è pronto: tabella public.quiz_entries non trovata. Esegui lo schema SQL nel Supabase SQL Editor e riprova (potrebbe volerci 1-2 minuti per aggiornare la cache).";
  }

  if (
    err &&
    (err.code === "PGRST106" ||
      (typeof err.hint === "string" && err.hint.includes("Only the following schemas are exposed")))
  ) {
    return "Supabase: lo schema 'public' non è esposto alle API. In Supabase vai su Project Settings → API → 'Exposed schemas' e aggiungi 'public', salva e attendi 1-2 minuti.";
  }

  if (err && typeof err.code === "string" && err.code.startsWith("PGRST") && typeof err.message === "string") {
    return `Supabase: ${err.code} — ${err.message}`;
  }

  return null;
}

function configFriendlyError(err) {
  const msg = err && typeof err.message === "string" ? err.message : "";
  if (msg.startsWith("Missing env var: ")) {
    const key = msg.replace("Missing env var: ", "").trim();
    return `Configurazione server incompleta: manca la variabile d'ambiente ${key}.`;
  }

  if (/Invalid API key|Invalid JWT|JWT|Unauthorized/i.test(msg) || /row level security/i.test(msg)) {
    return (
      "Supabase: credenziali non valide o insufficienti. Assicurati di usare SUPABASE_SERVICE_ROLE_KEY (chiave service_role) " +
      "e che SUPABASE_URL sia corretto."
    );
  }
  return null;
}

async function sendWinnerEmail({ to, prizeName, token, prizeValidUntil }) {
  if (!RESEND_API_KEY || !FROM_EMAIL) {
    throw new Error("Resend non configurato: imposta RESEND_API_KEY e FROM_EMAIL nel .env");
  }

  const untilIt = prizeValidUntil ? new Date(prizeValidUntil).toLocaleString("it-IT") : "";
  const subject = "Il tuo token premio — PuccioQuiz";
  const text =
    `Complimenti! Hai vinto: ${prizeName}\n\n` +
    `Il tuo token da riscattare è: ${token}\n` +
    (untilIt ? `Valido fino al: ${untilIt}\n` : "") +
    `\nMostra questo token in negozio per riscattare il premio.`;

  const html =
    `<div style="font-family:system-ui,-apple-system,Segoe UI,Roboto,Arial,sans-serif;line-height:1.45">` +
    `<h2 style="margin:0 0 12px 0">Complimenti! Hai vinto: <span style="color:#b3002d">${escapeHtml(
      prizeName
    )}</span></h2>` +
    `<p style="margin:0 0 12px 0">Ecco il tuo token da riscattare in negozio:</p>` +
    `<div style="font-size:22px;letter-spacing:3px;font-family:ui-monospace,SFMono-Regular,Menlo,monospace;padding:12px 14px;border:1px dashed #d4af37;border-radius:10px;display:inline-block;background:#111;color:#d4af37">${escapeHtml(
      token
    )}</div>` +
    (untilIt
      ? `<p style="margin:12px 0 0 0;color:#666">Valido fino al: <strong>${escapeHtml(untilIt)}</strong></p>`
      : "") +
    `<p style="margin:16px 0 0 0;color:#666">Conserva questa email e mostra il token alla cassa.</p>` +
    `</div>`;

  const r = await fetch("https://api.resend.com/emails", {
    method: "POST",
    headers: {
      Authorization: `Bearer ${RESEND_API_KEY}`,
      "Content-Type": "application/json",
    },
    body: JSON.stringify({
      from: FROM_EMAIL,
      to: [to],
      subject,
      text,
      html,
    }),
  });

  if (!r.ok) {
    const body = await r.text().catch(() => "");
    const err = new Error(`Resend error: HTTP ${r.status} ${body}`.slice(0, 600));
    err.httpStatus = r.status;
    throw err;
  }
}

// ---- Rate limiting (in-memory) ----
// Nota: in un ambiente con più istanze, questo è best-effort.
const rlIp = new Map(); // ip -> { count, resetAt }
const rlEmailQuiz = new Map(); // email -> { count, resetAt }
const rlEmailSpin = new Map(); // email -> { count, resetAt }

function rlCheck(map, key, max, now) {
  if (!key) return { ok: true };
  const cur = map.get(key);
  if (!cur || cur.resetAt <= now) {
    map.set(key, { count: 1, resetAt: now + RL_WINDOW_MS });
    return { ok: true };
  }
  cur.count++;
  if (cur.count > max) return { ok: false, retryAfterMs: cur.resetAt - now };
  return { ok: true };
}

function rateLimitMiddleware(req, res, next) {
  const now = Date.now();
  const ip = getClientIp(req);
  const ipHit = rlCheck(rlIp, ip, RL_MAX_PER_IP, now);
  if (!ipHit.ok) {
    res.setHeader("Retry-After", String(Math.ceil(ipHit.retryAfterMs / 1000)));
    return res.status(429).json({ error: "Troppe richieste. Riprova tra poco." });
  }
  return next();
}

function rateLimitEmail(map, max) {
  return function (req, res, next) {
    const now = Date.now();
    const email = req.body && req.body.email ? normalizeEmail(req.body.email) : "";
    const hit = rlCheck(map, email, max, now);
    if (!hit.ok) {
      res.setHeader("Retry-After", String(Math.ceil(hit.retryAfterMs / 1000)));
      return res.status(429).json({ error: "Troppe richieste per questa email. Riprova tra poco." });
    }
    return next();
  };
}

// ---- Quiz validation (server-side) ----
const QUIZ_CORRECT = {
  q1: "puccia",
  q2: "caffe_ghiaccio_mandorla",
  q3: "friselle",
  q4: "pasticciotto",
  q5: "pizzica",
  q6: "negroamaro",
  q7: "pezzetti",
  q8: "ricotta_fote",
  q9: "olio_evo",
};

function computeTestPassedFromAnswers(answers) {
  if (!answers || typeof answers !== "object") return null;
  for (let i = 1; i <= 9; i++) {
    const k = "q" + i;
    if (typeof answers[k] !== "string" || !answers[k]) return null;
  }
  let score = 0;
  for (let i = 1; i <= 9; i++) {
    const k = "q" + i;
    if (String(answers[k]) === String(QUIZ_CORRECT[k])) score++;
  }
  return score === 9;
}

// ---- Storage adapter ----
function createStore() {
  const canUseSupabase = SUPABASE_URL && SUPABASE_SERVICE_ROLE_KEY;

  if (canUseSupabase) {
    if (!EMAIL_FINGERPRINT_PEPPER) {
      console.warn("[puccioquiz] Config incompleta: manca EMAIL_FINGERPRINT_PEPPER (necessaria per /api/*).");
    }

    const supabase = createClient(SUPABASE_URL, SUPABASE_SERVICE_ROLE_KEY, {
      auth: { persistSession: false },
    });
    const TABLE = "quiz_entries";

    (async () => {
      try {
        const { error } = await supabase.from(TABLE).select("id").limit(1);
        if (error) {
          console.error("[puccioquiz] Supabase sanity check failed", {
            code: error.code,
            message: error.message,
            details: error.details,
            hint: error.hint,
          });
        }
      } catch (e) {
        console.error("[puccioquiz] Supabase sanity check threw", e);
      }
    })();

    async function insertWithFallback(payload) {
      // Proviamo a salvare email_plain (richiesta), ma se la colonna non esiste (schema vecchio) non blocchiamo tutto.
      const { error } = await supabase.from(TABLE).insert(payload);
      if (!error) return;

      const msg = (error && (error.message || "")) + "";
      const mentionsEmailPlain =
        msg.toLowerCase().includes("email_plain") && (msg.toLowerCase().includes("does not exist") || msg.toLowerCase().includes("unknown"));

      if (mentionsEmailPlain) {
        const copy = { ...payload };
        delete copy.email_plain;
        const { error: error2 } = await supabase.from(TABLE).insert(copy);
        if (!error2) {
          console.warn("[puccioquiz] Nota: colonna email_plain mancante su Supabase. Inserimento completato senza email_plain.");
          return;
        }
        throw error2;
      }
      throw error;
    }

    return {
      mode: "supabase",
      async getByFingerprint(fp) {
        const { data, error } = await supabase
          .from(TABLE)
          .select("id,email_fingerprint,test_passed,wheel_done,prize_name,token,prize_valid_until,created_at")
          .eq("email_fingerprint", fp)
          .maybeSingle();
        if (error) throw error;
        return data || null;
      },
      async insertParticipation(p) {
        await insertWithFallback(p);
      },
      async setSpinResult(fp, update) {
        const { data, error } = await supabase
          .from(TABLE)
          .update({ ...update, wheel_done: true })
          .eq("email_fingerprint", fp)
          .select("id,email_fingerprint,test_passed,wheel_done,prize_name,token,prize_valid_until")
          .maybeSingle();
        if (error) throw error;
        return data || null;
      },
    };
  }

  const mem = new Map(); // fp -> record
  return {
    mode: "memory",
    async getByFingerprint(fp) {
      return mem.get(fp) || null;
    },
    async insertParticipation(p) {
      mem.set(p.email_fingerprint, {
        id: p.email_fingerprint,
        email_fingerprint: p.email_fingerprint,
        test_passed: p.test_passed,
        wheel_done: p.wheel_done,
        prize_name: null,
        token: null,
        prize_valid_until: null,
        created_at: p.created_at || new Date().toISOString(),
      });
    },
    async setSpinResult(fp, update) {
      const cur = mem.get(fp);
      if (!cur) return null;
      const next = { ...cur, ...update, wheel_done: true };
      mem.set(fp, next);
      return next;
    },
  };
}

const store = createStore();

function missingEnvVars() {
  const required = [];
  const email = [];

  if (store?.mode === "supabase") {
    if (!EMAIL_FINGERPRINT_PEPPER) required.push("EMAIL_FINGERPRINT_PEPPER");
  }

  if (!RESEND_API_KEY) email.push("RESEND_API_KEY");
  if (!FROM_EMAIL) email.push("FROM_EMAIL");

  return { required, email };
}

// ---- Express app ----
const app = express();
app.disable("x-powered-by");
app.set("trust proxy", 1);

// Header di sicurezza base (senza helmet)
app.use((req, res, next) => {
  res.setHeader("X-Content-Type-Options", "nosniff");
  res.setHeader("X-Frame-Options", "DENY");
  res.setHeader("Referrer-Policy", "no-referrer");
  res.setHeader("Permissions-Policy", "geolocation=(), microphone=(), camera=()");
  // CSP: permissiva perché le pagine sono inline (CSS/JS). Se vuoi, possiamo stringerla dopo.
  res.setHeader(
    "Content-Security-Policy",
    "default-src 'self' https: data:; img-src 'self' https: data:; style-src 'self' 'unsafe-inline' https:; script-src 'self' 'unsafe-inline' https:; connect-src 'self' https:; frame-ancestors 'none'; base-uri 'self';"
  );
  next();
});

// CORS: non protegge da attacchi server-to-server, ma evita chiamate browser cross-site.
const ALLOWED_ORIGINS = (process.env.ALLOWED_ORIGINS || "")
  .split(",")
  .map((s) => s.trim())
  .filter(Boolean);
app.use(
  cors({
    origin: function (origin, cb) {
      // origin assente = same-origin o curl/postman: lo lasciamo passare.
      if (!origin) return cb(null, true);
      if (ALLOWED_ORIGINS.length === 0) return cb(null, true); // default permissivo per non rompere ambienti
      return cb(null, ALLOWED_ORIGINS.includes(origin));
    },
  })
);

app.use(express.json({ limit: "128kb" }));
app.use(rateLimitMiddleware);

// Serve i file statici dal root progetto
app.use(express.static(path.join(__dirname, "../public")))
app.get("/api/health", (req, res) => {
  okJson(res, { ok: true, service: "puccioquiz-backend", mode: store.mode, missingEnv: missingEnvVars() });
});

app.post("/api/quiz-finish", rateLimitEmail(rlEmailQuiz, RL_MAX_QUIZ_FINISH_PER_EMAIL), async (req, res) => {
  try {
    const { email, answers, testPassed, q10Values } = req.body || {};
    if (!isValidEmail(email)) return res.status(400).json({ error: "Email non valida." });

    if (store.mode === "supabase") requireEnv("EMAIL_FINGERPRINT_PEPPER", EMAIL_FINGERPRINT_PEPPER);

    // Calcolo server-side: non ci fidiamo del client
    let computed = computeTestPassedFromAnswers(answers);
    if (computed === null) {
      if (ALLOW_LEGACY_TESTPASSED) {
        computed = !!testPassed;
      } else {
        return res.status(400).json({ error: "Richiesta non valida: mancano le risposte del quiz." });
      }
    }

    const fp = store.mode === "supabase" ? emailFingerprint(email) : normalizeEmail(email);
    const existing = await store.getByFingerprint(fp);
    if (existing) {
      // Risposta user-friendly (usata dal frontend per mostrare popup carino)
      return okJson(res, {
        ok: true,
        alreadyParticipated: true,
        testPassed: Number(existing.test_passed) === 1 || existing.test_passed === true,
        wheelDone: !!existing.wheel_done,
        prize_name: existing.prize_name || null,
        prize_valid_until: existing.prize_valid_until || null,
      });
    }

    const createdAt = new Date().toISOString();
    const ip = req.headers["x-forwarded-for"] ? String(req.headers["x-forwarded-for"]).split(",")[0].trim() : getClientIp(req);

    await store.insertParticipation({
      email_fingerprint: fp,
      // Richiesto: email in chiaro (se la colonna esiste)
      email_plain: normalizeEmail(email),
      // Colonne legacy cifrate (se presenti nello schema): teniamole null
      email_enc: null,
      email_iv: null,
      email_tag: null,
      test_passed: computed,
      q10_values: Array.isArray(q10Values) ? q10Values : [],
      ip_address: ip,
      created_at: createdAt,
      wheel_done: false,
    });

    okJson(res, { ok: true, alreadyParticipated: false, testPassed: computed });
  } catch (err) {
    console.error(err);
    const friendly = supabaseFriendlyError(err) || configFriendlyError(err);
    res.status(500).json({ error: friendly || "Errore server." });
  }
});

app.post("/api/participation-state", rateLimitEmail(rlEmailQuiz, RL_MAX_QUIZ_FINISH_PER_EMAIL), async (req, res) => {
  try {
    const { email } = req.body || {};
    if (!isValidEmail(email)) return res.status(400).json({ error: "Email non valida." });
    const fp = store.mode === "supabase" ? emailFingerprint(email) : normalizeEmail(email);
    const row = await store.getByFingerprint(fp);
    if (!row) return okJson(res, { exists: false });

    okJson(res, {
      exists: true,
      testPassed: Number(row.test_passed) === 1 || row.test_passed === true,
      wheelDone: !!row.wheel_done,
      prize_name: row.prize_name || null,
      prize_valid_until: row.prize_valid_until || null,
    });
  } catch (err) {
    console.error(err);
    const friendly = supabaseFriendlyError(err) || configFriendlyError(err);
    res.status(500).json({ error: friendly || "Errore server." });
  }
});

app.post("/api/spin-result", rateLimitEmail(rlEmailSpin, RL_MAX_SPIN_PER_EMAIL), async (req, res) => {
  try {
    const { email, prizeName } = req.body || {};
    if (!isValidEmail(email)) return res.status(400).json({ error: "Email non valida." });
    const fp = store.mode === "supabase" ? emailFingerprint(email) : normalizeEmail(email);
    const row = await store.getByFingerprint(fp);
    if (!row) return res.status(404).json({ error: "Partecipazione non trovata." });
    if (!(Number(row.test_passed) === 1 || row.test_passed === true)) return res.status(403).json({ error: "Quiz non superato." });
    if (row.wheel_done) return res.status(409).json({ error: "Hai già girato la ruota con questa email." });

    // Nota: il premio arriva dal client (ruota). Per evitare valori strani, lo sanitizziamo.
    // Se vuoi massima correttezza (anti-frode), possiamo far scegliere il premio al server e far ruotare la ruota di conseguenza.
    const safePrize = String(prizeName || "").slice(0, 80);
    if (!safePrize) return res.status(400).json({ error: "Premio non valido." });

    const token = makeToken();
    const until = validUntilIso(PRIZE_VALIDITY_DAYS);

    const updated = await store.setSpinResult(fp, { prize_name: safePrize, token, prize_valid_until: until });
    if (!updated) return res.status(500).json({ error: "Impossibile salvare il risultato." });

    // Invia token SOLO via email (non lo esponiamo mai al browser)
    try {
      await sendWinnerEmail({ to: normalizeEmail(email), prizeName: safePrize, token, prizeValidUntil: until });
      okJson(res, { ok: true, prize_valid_until: until });
    } catch (mailErr) {
      console.error(mailErr);
      res.status(502).json({
        error: "Premio assegnato, ma invio email non riuscito. Usa il pulsante 'Reinvia email' oppure riprova tra poco.",
        prize_valid_until: until,
      });
    }
  } catch (err) {
    console.error(err);
    const friendly = supabaseFriendlyError(err) || configFriendlyError(err);
    res.status(500).json({ error: friendly || "Errore server." });
  }
});

app.post("/api/resend-token", rateLimitEmail(rlEmailSpin, RL_MAX_SPIN_PER_EMAIL), async (req, res) => {
  try {
    const { email } = req.body || {};
    if (!isValidEmail(email)) return res.status(400).json({ error: "Email non valida." });
    const fp = store.mode === "supabase" ? emailFingerprint(email) : normalizeEmail(email);
    const row = await store.getByFingerprint(fp);
    if (!row) return res.status(404).json({ error: "Partecipazione non trovata." });
    if (!row.wheel_done || !row.token) return res.status(409).json({ error: "Nessun token da reinviare." });

    await sendWinnerEmail({
      to: normalizeEmail(email),
      prizeName: row.prize_name || "Premio",
      token: row.token,
      prizeValidUntil: row.prize_valid_until || null,
    });

    okJson(res, { ok: true });
  } catch (err) {
    console.error(err);
    const friendly = supabaseFriendlyError(err) || configFriendlyError(err);
    res.status(500).json({ error: friendly || "Invio email non riuscito." });
  }
});

// Fallback: apri il quiz
app.get("/", (req, res) => {
  res.sendFile(path.join(__dirname, "..", "test.html"));
});

// Avvia il server solo se NON siamo su Vercel (per compatibilità con Render)
if (!process.env.VERCEL) {
  app.listen(PORT, () => {
    console.log(`[puccioquiz] server in ascolto su http://127.0.0.1:${PORT} (mode=${store.mode})`);
    if (store.mode === "memory") {
      console.log("[puccioquiz] Nota: Supabase non configurato. I dati NON saranno persistenti.");
    }
  });
}

// Fondamentale per Vercel: esporta l'app Express
module.exports = app;

