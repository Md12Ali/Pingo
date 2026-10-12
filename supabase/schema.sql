-- =============================================================================
-- Pingo: Supabase schema
-- Run once in a fresh project: Supabase Dashboard > SQL Editor > New query > Run
--
-- Who writes what:
--   * The mobile app (anon key + user JWT) reads data and edits its own profile.
--   * The Node server (service_role key, bypasses RLS) inserts messages,
--     updates message status and writes call logs.
-- =============================================================================

create extension if not exists pgcrypto;

-- -----------------------------------------------------------------------------
-- Enums
-- -----------------------------------------------------------------------------
create type public.message_type   as enum ('text', 'image', 'video');
create type public.message_status as enum ('sent', 'delivered', 'read');
create type public.call_type      as enum ('voice', 'video');
create type public.call_status    as enum ('ringing', 'answered', 'declined', 'missed', 'ended', 'failed');

-- -----------------------------------------------------------------------------
-- users: public profile, one row per auth.users row
-- Email and phone stay in auth.users on purpose. Every signed-in user can read
-- this table (needed to find people by tag), so nothing private belongs here.
-- -----------------------------------------------------------------------------
create table public.users (
  id            uuid primary key references auth.users (id) on delete cascade,
  display_name  text check (char_length(display_name) between 1 and 50),
  tag           text unique check (tag ~ '^[a-z0-9_]{3,20}$'),  -- e.g. "md_ali", shown as @md_ali
  avatar_url    text,
  last_seen_at  timestamptz,
  created_at    timestamptz not null default now(),
  updated_at    timestamptz not null default now()
);

comment on column public.users.tag is
  'Unique handle, lowercase letters/digits/underscore, 3-20 chars. NULL until profile setup is finished.';

-- -----------------------------------------------------------------------------
-- messages: 1-on-1 messages
-- -----------------------------------------------------------------------------
create table public.messages (
  id              uuid primary key default gen_random_uuid(),
  client_id       uuid,                      -- generated on the phone; makes retries idempotent
  sender_id       uuid not null references public.users (id) on delete cascade,
  receiver_id     uuid not null references public.users (id) on delete cascade,
  type            public.message_type   not null default 'text',
  content         text,                      -- message text, or caption for media
  media_path      text,                      -- object path inside the "chat-media" bucket
  thumbnail_path  text,                      -- poster frame for videos
  media_meta      jsonb,                     -- { width, height, duration, size, mime }
  status          public.message_status not null default 'sent',
  created_at      timestamptz not null default now(),
  delivered_at    timestamptz,
  read_at         timestamptz,

  constraint messages_not_to_self check (sender_id <> receiver_id),
  constraint messages_has_body check (
    (type = 'text' and content is not null and char_length(content) between 1 and 4000)
    or
    (type in ('image', 'video') and media_path is not null)
  ),
  constraint messages_client_id_unique unique (sender_id, client_id)
);

-- Load one conversation, newest first (both directions share this index).
create index messages_conversation_idx on public.messages (
  least(sender_id, receiver_id),
  greatest(sender_id, receiver_id),
  created_at desc
);

-- Undelivered / unread messages for a user (used on reconnect and for badges).
create index messages_pending_idx on public.messages (receiver_id, created_at)
  where status <> 'read';

-- -----------------------------------------------------------------------------
-- call_logs: one row per call attempt
-- -----------------------------------------------------------------------------
create table public.call_logs (
  id                uuid primary key default gen_random_uuid(),
  caller_id         uuid not null references public.users (id) on delete cascade,
  callee_id         uuid not null references public.users (id) on delete cascade,
  type              public.call_type   not null,
  status            public.call_status not null default 'ringing',
  channel_name      text not null,           -- Agora channel both sides join
  started_at        timestamptz not null default now(),   -- ringing began
  answered_at       timestamptz,
  ended_at          timestamptz,
  duration_seconds  integer generated always as (
    case
      when answered_at is not null and ended_at is not null
        then greatest(0, floor(extract(epoch from (ended_at - answered_at)))::integer)
      else 0
    end
  ) stored,

  constraint call_logs_not_to_self check (caller_id <> callee_id)
);

create index call_logs_caller_idx on public.call_logs (caller_id, started_at desc);
create index call_logs_callee_idx on public.call_logs (callee_id, started_at desc);

-- -----------------------------------------------------------------------------
-- Triggers
-- -----------------------------------------------------------------------------

-- Create the profile row automatically when someone signs up (email or phone).
create function public.handle_new_user()
returns trigger
language plpgsql
security definer
set search_path = ''
as $$
begin
  insert into public.users (id) values (new.id)
  on conflict (id) do nothing;
  return new;
end;
$$;

create trigger on_auth_user_created
  after insert on auth.users
  for each row execute function public.handle_new_user();

-- Keep users.updated_at current.
create function public.set_updated_at()
returns trigger
language plpgsql
set search_path = ''
as $$
begin
  new.updated_at = now();
  return new;
end;
$$;

create trigger users_set_updated_at
  before update on public.users
  for each row execute function public.set_updated_at();

-- -----------------------------------------------------------------------------
-- Row Level Security
-- -----------------------------------------------------------------------------
alter table public.users     enable row level security;
alter table public.messages  enable row level security;
alter table public.call_logs enable row level security;

-- users: any signed-in user can look people up; you can only edit yourself.
create policy "users: read all profiles"
  on public.users for select
  to authenticated
  using (true);

create policy "users: update own profile"
  on public.users for update
  to authenticated
  using (id = (select auth.uid()))
  with check (id = (select auth.uid()));

-- messages: participants can read. No insert/update/delete policy, so only the
-- server (service_role) can write. That stops clients forging status or sender.
create policy "messages: participants can read"
  on public.messages for select
  to authenticated
  using ((select auth.uid()) in (sender_id, receiver_id));

-- call_logs: participants can read; server writes.
create policy "call_logs: participants can read"
  on public.call_logs for select
  to authenticated
  using ((select auth.uid()) in (caller_id, callee_id));

-- -----------------------------------------------------------------------------
-- Storage buckets
--   avatars     public   path: {user_id}/{filename}
--   chat-media  private  path: {sender_id}/{receiver_id}/{filename}
-- 50 MB is the per-file ceiling on the Supabase free plan.
-- -----------------------------------------------------------------------------
insert into storage.buckets (id, name, public, file_size_limit, allowed_mime_types)
values
  ('avatars', 'avatars', true, 5242880,
     array['image/jpeg', 'image/png', 'image/webp']),
  ('chat-media', 'chat-media', false, 52428800,
     array['image/jpeg', 'image/png', 'image/webp', 'image/heic', 'video/mp4', 'video/quicktime'])
on conflict (id) do nothing;

-- avatars: anyone can view (public bucket); you manage files in your own folder.
create policy "avatars: upload own"
  on storage.objects for insert
  to authenticated
  with check (
    bucket_id = 'avatars'
    and (storage.foldername(name))[1] = (select auth.uid())::text
  );

create policy "avatars: update own"
  on storage.objects for update
  to authenticated
  using (
    bucket_id = 'avatars'
    and (storage.foldername(name))[1] = (select auth.uid())::text
  );

create policy "avatars: delete own"
  on storage.objects for delete
  to authenticated
  using (
    bucket_id = 'avatars'
    and (storage.foldername(name))[1] = (select auth.uid())::text
  );

-- chat-media: sender uploads into {sender_id}/{receiver_id}/...; only the two
-- people in the path can read (the app requests short-lived signed URLs).
create policy "chat-media: sender uploads"
  on storage.objects for insert
  to authenticated
  with check (
    bucket_id = 'chat-media'
    and (storage.foldername(name))[1] = (select auth.uid())::text
  );

create policy "chat-media: participants read"
  on storage.objects for select
  to authenticated
  using (
    bucket_id = 'chat-media'
    and (select auth.uid())::text in (
      (storage.foldername(name))[1],
      (storage.foldername(name))[2]
    )
  );

create policy "chat-media: sender deletes"
  on storage.objects for delete
  to authenticated
  using (
    bucket_id = 'chat-media'
    and (storage.foldername(name))[1] = (select auth.uid())::text
  );
