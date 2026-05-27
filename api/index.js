/* PuccioQuiz backend (Express + Supabase + Resend)
   HARDENING 2026-05:
   - Rate limiting (in-memory) per IP + per email per ridurre abuso/enumeration
   - Non fidarsi di testPassed dal client: calcolo lato server (richiede answers dal frontend)
   - Risposta "già partecipato" user-friendly (senza errore finto di connessione)
   - trust proxy per Render (x-forwarded-for)
   - Header di sicurezza di base (senza dipendenze extra)
   UPDATE 2026-05b:
   - Email anche ai perdenti (GDPR: raccolta dati per marketing)
   - Endpoint /api/unsubscribe con token sicuro
   - Controllo unsubscribed prima di ogni invio email
   - Reply-To e List-Unsubscribe headers
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
const BASE_URL = (process.env.BASE_URL || "https://quiz.pucciotto.it").trim();
const REPLY_TO = "info@pucciotto.it";

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

// Genera un token di disiscrizione sicuro (32 byte hex)
function makeUnsubscribeToken() {
  return crypto.randomBytes(32).toString("hex");
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
    return "Supabase: lo schema 'public' non è esposto alle API. In Supabase vai su Project Settings -> API -> 'Exposed schemas' e aggiungi 'public', salva e attendi 1-2 minuti.";
  }

  if (err && typeof err.code === "string" && err.code.startsWith("PGRST") && typeof err.message === "string") {
    return `Supabase: ${err.code} -- ${err.message}`;
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

// ---- Template email base ----
function emailBaseTemplate({ headerColor = "#C0392B", content, unsubscribeToken }) {
  const unsubUrl = unsubscribeToken ? `${BASE_URL}/api/unsubscribe?t=${unsubscribeToken}` : null;
  const footerUnsub = unsubUrl
    ? `<p style="font-size:11px;color:#aaaaaa;margin:6px 0 0 0;">
        <a href="${unsubUrl}" style="color:#aaaaaa;text-decoration:underline;">Non vuoi ricevere comunicazioni da Pucciotto? Disiscrivi</a>
       </p>`
    : "";

  return `<!DOCTYPE html>
<html lang="it">
<head>
<meta charset="UTF-8" />
<meta name="viewport" content="width=device-width, initial-scale=1.0"/>
</head>
<body style="margin:0;padding:0;background-color:#fafaf8;font-family:'Segoe UI',Arial,sans-serif;">
<table width="100%" cellpadding="0" cellspacing="0" border="0" style="background-color:#fafaf8;">
  <tr><td align="center" style="padding:32px 16px;">
    <table width="560" cellpadding="0" cellspacing="0" border="0" style="max-width:560px;width:100%;background-color:#ffffff;border-radius:16px;overflow:hidden;box-shadow:0 4px 24px rgba(0,0,0,0.07);">
      <tr>
        <td align="center" style="background-color:${headerColor};padding:28px 32px;">
          <img src="https://quiz.pucciotto.it/logo.png" alt="Pucciotto" width="160" style="display:block;margin:0 auto;max-width:160px;height:auto;" />
          <div style="font-size:13px;color:rgba(255,255,255,0.8);margin-top:10px;">La puccia 2.0 -- Lecce</div>
        </td>
      </tr>
      <tr>
        <td style="padding:28px 32px;background-color:#ffffff;">
          ${content}
        </td>
      </tr>
      <tr>
        <td align="center" style="background-color:#fafaf8;padding:20px 32px;border-top:1px solid #f0ece8;">
          <p style="font-size:12px;color:#aaaaaa;margin:0;line-height:1.8;">
            Pucciotto Srls · Via dei Biccari 15, 73100 Lecce · P.IVA 05465530755
          </p>
          <p style="font-size:12px;color:#aaaaaa;margin:6px 0 0 0;">
            <a href="mailto:info@pucciotto.it" style="color:#C0392B;text-decoration:none;">info@pucciotto.it</a>
          </p>
          ${footerUnsub}
        </td>
      </tr>
    </table>
  </td></tr>
</table>
</body>
</html>`;
}

// ---- Invio email via Resend ----
async function sendResendEmail({ to, subject, html, text, unsubscribeToken }) {
  if (!RESEND_API_KEY || !FROM_EMAIL) {
    throw new Error("Resend non configurato: imposta RESEND_API_KEY e FROM_EMAIL nel .env");
  }

  const unsubUrl = unsubscribeToken ? `${BASE_URL}/api/unsubscribe?t=${unsubscribeToken}` : null;

  const body = {
    from: FROM_EMAIL,
    to: [to],
    reply_to: REPLY_TO,
    subject,
    text,
    html,
  };

  if (unsubUrl) {
    body.headers = {
      "List-Unsubscribe": `<${unsubUrl}>, <mailto:${REPLY_TO}?subject=unsubscribe>`,
      "List-Unsubscribe-Post": "List-Unsubscribe=One-Click",
    };
  }

  const r = await fetch("https://api.resend.com/emails", {
    method: "POST",
    headers: {
      Authorization: `Bearer ${RESEND_API_KEY}`,
      "Content-Type": "application/json",
    },
    body: JSON.stringify(body),
  });

  if (!r.ok) {
    const resBody = await r.text().catch(() => "");
    const err = new Error(`Resend error: HTTP ${r.status} ${resBody}`.slice(0, 600));
    err.httpStatus = r.status;
    throw err;
  }
}

// ---- Email vincitore ----
async function sendWinnerEmail({ to, prizeName, token, prizeValidUntil, unsubscribeToken }) {
  const untilIt = prizeValidUntil ? new Date(prizeValidUntil).toLocaleString("it-IT") : "";
  const subject = "Il tuo regalo da Pucciotto ti aspetta";

  const text =
    `Hai completato il PuccioQuiz!\n\n` +
    `Il tuo regalo e: ${prizeName}\n` +
    `Codice da mostrare in negozio: ${token}\n` +
    (untilIt ? `Valido fino al: ${untilIt}\n` : "") +
    `\nCi vediamo da Pucciotto a Lecce!\n\n` +
    `Pucciotto Srls · Via dei Biccari 15, Lecce · info@pucciotto.it\n` +
    (unsubscribeToken ? `\nPer disiscriverti: ${BASE_URL}/api/unsubscribe?t=${unsubscribeToken}` : "");

  const content = `
    <p style="font-size:16px;font-weight:700;color:#1a1a1a;margin:0 0 6px 0;">Complimenti!</p>
    <p style="font-size:14px;color:#555555;margin:0 0 24px 0;line-height:1.5;">
      Hai completato il PuccioQuiz e hai vinto un regalo.<br/>Mostra il codice qui sotto in negozio per ritirarlo.
    </p>
    <hr style="border:none;border-top:1px solid #f0ece8;margin:0 0 24px 0;"/>
    <table width="100%" cellpadding="0" cellspacing="0" border="0" style="background-color:#fff8f4;border:1px solid #fde8e2;border-radius:12px;margin-bottom:20px;">
      <tr><td align="center" style="padding:20px 24px;">
        <div style="font-size:44px;margin-bottom:10px;">🎁</div>
        <div style="font-size:11px;font-weight:700;text-transform:uppercase;letter-spacing:2px;color:#C0392B;margin-bottom:6px;">Il tuo regalo</div>
        <div style="font-size:22px;font-weight:700;color:#1a1a1a;">${escapeHtml(prizeName)}</div>
      </td></tr>
    </table>
    <table width="100%" cellpadding="0" cellspacing="0" border="0" style="background-color:#fafaf8;border:2px dashed #e8e4e0;border-radius:12px;margin-bottom:24px;">
      <tr><td align="center" style="padding:18px 20px;">
        <div style="font-size:11px;font-weight:700;text-transform:uppercase;letter-spacing:2px;color:#999999;margin-bottom:8px;">Codice da mostrare in cassa</div>
        <div style="font-size:28px;font-weight:700;color:#C0392B;letter-spacing:4px;">${escapeHtml(token)}</div>
        ${untilIt ? `<div style="font-size:12px;color:#aaaaaa;margin-top:10px;">Valido fino al: <strong style="color:#555555;">${escapeHtml(untilIt)}</strong></div>` : ""}
      </td></tr>
    </table>
    <hr style="border:none;border-top:1px solid #f0ece8;margin:0 0 20px 0;"/>
    <p style="font-size:13px;color:#777777;margin:0;line-height:1.6;">
      Vieni a trovarci in <strong style="color:#1a1a1a;">Via dei Biccari 15, Lecce</strong> e mostra questo codice alla cassa per ritirare il tuo regalo.
    </p>
    <hr style="border:none;border-top:1px solid #f0ece8;margin:24px 0 20px 0;"/>
    <p style="font-size:13px;font-weight:700;color:#1a1a1a;margin:0 0 6px 0;">Resta aggiornato sui nostri social</p>
    <p style="font-size:13px;color:#777777;margin:0 0 10px 0;line-height:1.6;">
      Seguici per non perdere le novita, le promozioni e tutte le ultime news da Pucciotto!
    </p>
    <p style="margin:0;">
      <a href="https://www.tiktok.com/@pucciotto_lecce" style="display:inline-block;margin-right:12px;color:#C0392B;text-decoration:none;font-size:13px;font-weight:700;">TikTok</a>
      <a href="https://www.facebook.com/pucciottolecce/" style="display:inline-block;margin-right:12px;color:#C0392B;text-decoration:none;font-size:13px;font-weight:700;">Facebook</a>
      <a href="https://www.instagram.com/pucciotto_lecce/" style="display:inline-block;color:#C0392B;text-decoration:none;font-size:13px;font-weight:700;">Instagram</a>
    </p>
  `;

  const html = emailBaseTemplate({ content, unsubscribeToken });
  await sendResendEmail({ to, subject, html, text, unsubscribeToken });
}

// ---- Email perdente ----
async function sendLoserEmail({ to, unsubscribeToken }) {
  const subject = "Grazie per aver partecipato al PuccioQuiz";

  const text =
    `Ciao!\n\n` +
    `Hai partecipato al PuccioQuiz di Pucciotto.\n` +
    `Purtroppo non hai risposto correttamente a tutte le domande, ma non mollare!\n\n` +
    `Tienici d'occhio -- ci sono tante novita in arrivo per l'apertura di Pucciotto in Via dei Biccari 15, Lecce.\n\n` +
    `A presto!\n\n` +
    `Pucciotto Srls · Via dei Biccari 15, Lecce · info@pucciotto.it\n` +
    (unsubscribeToken ? `\nPer disiscriverti: ${BASE_URL}/api/unsubscribe?t=${unsubscribeToken}` : "");

  const content = `
    <p style="font-size:16px;font-weight:700;color:#1a1a1a;margin:0 0 10px 0;">Grazie per aver partecipato!</p>
    <p style="font-size:14px;color:#555555;margin:0 0 16px 0;line-height:1.6;">
      Hai partecipato al PuccioQuiz di Pucciotto. Purtroppo non hai risposto correttamente a tutte le domande, ma non mollare!
    </p>
    <table width="100%" cellpadding="0" cellspacing="0" border="0" style="background-color:#fff8f4;border:1px solid #fde8e2;border-radius:12px;margin-bottom:20px;">
      <tr><td align="center" style="padding:20px 24px;">
        <div style="font-size:15px;font-weight:700;color:#C0392B;margin-bottom:8px;">Pucciotto apre presto a Lecce</div>
        <div style="font-size:13px;color:#777777;line-height:1.6;">
          Tienici d'occhio -- ci sono tante novita in arrivo!<br/>
          Via dei Biccari 15, 73100 Lecce
        </div>
      </td></tr>
    </table>
    <p style="font-size:13px;color:#777777;margin:0 0 10px 0;line-height:1.6;">
      Seguici sui nostri social per non perdere le promozioni e le ultime news da Pucciotto!
    </p>
    <p style="margin:0;">
      <a href="https://www.tiktok.com/@pucciotto_lecce" style="display:inline-block;margin-right:12px;color:#C0392B;text-decoration:none;font-size:13px;font-weight:700;">TikTok</a>
      <a href="https://www.facebook.com/pucciottolecce/" style="display:inline-block;margin-right:12px;color:#C0392B;text-decoration:none;font-size:13px;font-weight:700;">Facebook</a>
      <a href="https://www.instagram.com/pucciotto_lecce/" style="display:inline-block;color:#C0392B;text-decoration:none;font-size:13px;font-weight:700;">Instagram</a>
    </p>
  `;

  const html = emailBaseTemplate({ content, unsubscribeToken });
  await sendResendEmail({ to, subject, html, text, unsubscribeToken });
}

// ---- Rate limiting (in-memory) ----
const rlIp = new Map();
const rlEmailQuiz = new Map();
const rlEmailSpin = new Map();

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
          .select("id,email_fingerprint,test_passed,wheel_done,prize_name,token,prize_valid_until,created_at,unsubscribed,unsubscribe_token")
          .eq("email_fingerprint", fp)
          .maybeSingle();
        if (error) throw error;
        return data || null;
      },
      async getByUnsubscribeToken(unsub_token) {
        const { data, error } = await supabase
          .from(TABLE)
          .select("id,email_fingerprint,unsubscribed")
          .eq("unsubscribe_token", unsub_token)
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
          .select("id,email_fingerprint,test_passed,wheel_done,prize_name,token,prize_valid_until,unsubscribed,unsubscribe_token")
          .maybeSingle();
        if (error) throw error;
        return data || null;
      },
      async setUnsubscribed(id) {
        const { error } = await supabase
          .from(TABLE)
          .update({ unsubscribed: true })
          .eq("id", id);
        if (error) throw error;
      },
    };
  }

  const mem = new Map();
  return {
    mode: "memory",
    async getByFingerprint(fp) {
      return mem.get(fp) || null;
    },
    async getByUnsubscribeToken(unsub_token) {
      for (const row of mem.values()) {
        if (row.unsubscribe_token === unsub_token) return row;
      }
      return null;
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
        unsubscribed: false,
        unsubscribe_token: p.unsubscribe_token || null,
      });
    },
    async setSpinResult(fp, update) {
      const cur = mem.get(fp);
      if (!cur) return null;
      const next = { ...cur, ...update, wheel_done: true };
      mem.set(fp, next);
      return next;
    },
    async setUnsubscribed(id) {
      const row = mem.get(id);
      if (row) mem.set(id, { ...row, unsubscribed: true });
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

app.use((req, res, next) => {
  res.setHeader("X-Content-Type-Options", "nosniff");
  res.setHeader("X-Frame-Options", "DENY");
  res.setHeader("Referrer-Policy", "no-referrer");
  res.setHeader("Permissions-Policy", "geolocation=(), microphone=(), camera=()");
  res.setHeader(
    "Content-Security-Policy",
    "default-src 'self' https: data:; img-src 'self' https: data:; style-src 'self' 'unsafe-inline' https:; script-src 'self' 'unsafe-inline' https:; connect-src 'self' https:; frame-ancestors 'none'; base-uri 'self';"
  );
  next();
});

const ALLOWED_ORIGINS = (process.env.ALLOWED_ORIGINS || "")
  .split(",")
  .map((s) => s.trim())
  .filter(Boolean);
app.use(
  cors({
    origin: function (origin, cb) {
      if (!origin) return cb(null, true);
      if (ALLOWED_ORIGINS.length === 0) return cb(null, true);
      return cb(null, ALLOWED_ORIGINS.includes(origin));
    },
  })
);

app.use(express.json({ limit: "128kb" }));
app.use(rateLimitMiddleware);

app.use(express.static(path.join(__dirname, "../public")))

app.get("/api/health", (req, res) => {
  okJson(res, { ok: true, service: "puccioquiz-backend", mode: store.mode, missingEnv: missingEnvVars() });
});

app.post("/api/quiz-finish", rateLimitEmail(rlEmailQuiz, RL_MAX_QUIZ_FINISH_PER_EMAIL), async (req, res) => {
  try {
    const { email, answers, testPassed, q10Values } = req.body || {};
    if (!isValidEmail(email)) return res.status(400).json({ error: "Email non valida." });

    if (store.mode === "supabase") requireEnv("EMAIL_FINGERPRINT_PEPPER", EMAIL_FINGERPRINT_PEPPER);

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
    const unsubscribeToken = makeUnsubscribeToken();

    await store.insertParticipation({
      email_fingerprint: fp,
      email_plain: normalizeEmail(email),
      email_enc: null,
      email_iv: null,
      email_tag: null,
      test_passed: computed,
      q10_values: Array.isArray(q10Values) ? q10Values : [],
      ip_address: ip,
      created_at: createdAt,
      wheel_done: false,
      unsubscribed: false,
      unsubscribe_token: unsubscribeToken,
    });

    // Se ha perso, manda email di consolazione
    if (!computed) {
      try {
        await sendLoserEmail({ to: normalizeEmail(email), unsubscribeToken });
      } catch (mailErr) {
        console.error("[puccioquiz] Email perdente non inviata:", mailErr.message);
        // Non blocchiamo la risposta per un errore email
      }
    }

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
    if (row.wheel_done) return res.status(409).json({ error: "Hai gia girato la ruota con questa email." });

    const safePrize = String(prizeName || "").slice(0, 80);
    if (!safePrize) return res.status(400).json({ error: "Premio non valido." });

    const token = makeToken();
    const until = validUntilIso(PRIZE_VALIDITY_DAYS);

    const updated = await store.setSpinResult(fp, { prize_name: safePrize, token, prize_valid_until: until });
    if (!updated) return res.status(500).json({ error: "Impossibile salvare il risultato." });

    // Se l'utente si e disiscritto non mandiamo email
    if (row.unsubscribed) {
      return okJson(res, { ok: true, prize_valid_until: until });
    }

    try {
      await sendWinnerEmail({
        to: normalizeEmail(email),
        prizeName: safePrize,
        token,
        prizeValidUntil: until,
        unsubscribeToken: row.unsubscribe_token,
      });
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

    if (row.unsubscribed) {
      return res.status(403).json({ error: "Utente disiscritto." });
    }

    await sendWinnerEmail({
      to: normalizeEmail(email),
      prizeName: row.prize_name || "Premio",
      token: row.token,
      prizeValidUntil: row.prize_valid_until || null,
      unsubscribeToken: row.unsubscribe_token,
    });

    okJson(res, { ok: true });
  } catch (err) {
    console.error(err);
    const friendly = supabaseFriendlyError(err) || configFriendlyError(err);
    res.status(500).json({ error: friendly || "Invio email non riuscito." });
  }
});

// ---- Disiscrizione ----
// GET: link cliccabile dall'email, apre una pagina di conferma
app.get("/api/unsubscribe", async (req, res) => {
  try {
    const t = String(req.query.t || "").trim();
    if (!t || t.length < 10) {
      return res.status(400).send(`<!DOCTYPE html><html lang="it"><body style="font-family:sans-serif;text-align:center;padding:60px 20px;">
        <h2>Link non valido</h2><p>Il link di disiscrizione non e valido o e scaduto.</p>
      </body></html>`);
    }

    const row = await store.getByUnsubscribeToken(t);
    if (!row) {
      return res.status(404).send(`<!DOCTYPE html><html lang="it"><body style="font-family:sans-serif;text-align:center;padding:60px 20px;">
        <h2>Link non trovato</h2><p>Non abbiamo trovato nessuna iscrizione associata a questo link.</p>
      </body></html>`);
    }

    if (row.unsubscribed) {
      return res.send(`<!DOCTYPE html><html lang="it"><body style="font-family:sans-serif;text-align:center;padding:60px 20px;">
        <h2>Gia disiscritto</h2><p>Sei gia stato rimosso dalla nostra lista. Non riceverai altre comunicazioni da Pucciotto.</p>
      </body></html>`);
    }

    await store.setUnsubscribed(row.id);

    return res.send(`<!DOCTYPE html><html lang="it"><body style="font-family:sans-serif;text-align:center;padding:60px 20px;background:#fafaf8;">
      <div style="max-width:400px;margin:0 auto;background:#fff;border-radius:16px;padding:40px 32px;box-shadow:0 4px 24px rgba(0,0,0,0.07);">
        <div style="font-size:48px;margin-bottom:16px;">👋</div>
        <h2 style="color:#1a1a1a;margin-bottom:12px;">Disiscrizione completata</h2>
        <p style="color:#777;font-size:14px;line-height:1.6;">Hai rimosso il tuo consenso alle comunicazioni di Pucciotto. Non riceverai altre email da noi.</p>
        <p style="color:#aaa;font-size:12px;margin-top:20px;">Pucciotto Srls · Via dei Biccari 15, Lecce</p>
      </div>
    </body></html>`);
  } catch (err) {
    console.error("[puccioquiz] Errore disiscrizione:", err);
    res.status(500).send("Errore server. Riprova tra poco.");
  }
});

app.get("/", (req, res) => {
  res.sendFile(path.join(__dirname, "..", "test.html"));
});

if (!process.env.VERCEL) {
  app.listen(PORT, () => {
    console.log(`[puccioquiz] server in ascolto su http://127.0.0.1:${PORT} (mode=${store.mode})`);
    if (store.mode === "memory") {
      console.log("[puccioquiz] Nota: Supabase non configurato. I dati NON saranno persistenti.");
    }
  });
}

module.exports = app;
