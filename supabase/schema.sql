-- Schema Supabase per PuccioQuiz
-- Esegui questo SQL nel pannello Supabase (SQL Editor).

create extension if not exists pgcrypto;

create table if not exists public.quiz_entries (
  id uuid primary key default gen_random_uuid(),
  created_at timestamptz not null default now(),

  -- Impronta non reversibile per lookup/unique (HMAC-SHA256 con pepper lato server)
  email_fingerprint text not null unique,

  -- Email cifrata (AES-256-GCM) lato server Node: non esporre al client
  email_enc text,
  email_iv text,
  email_tag text,

  test_passed boolean not null default false,
  q10_values jsonb not null default '[]'::jsonb,

  -- IP address opzionale per logging
  ip_address text,

  wheel_done boolean not null default false,
  prize_name text,
  token text,
  prize_valid_until timestamptz
);

create index if not exists quiz_entries_email_fingerprint_idx
  on public.quiz_entries (email_fingerprint);

create index if not exists quiz_entries_wheel_done_idx
  on public.quiz_entries (wheel_done);

-- Sicurezza: abilita RLS e NON creare policy pubbliche.
-- Il backend usa la SERVICE ROLE KEY (bypassa RLS), mentre il browser non deve mai avere accesso.
alter table public.quiz_entries enable row level security;

alter table public.quiz_entries
  add column if not exists email_plain text;
