-- Agenda Institucional SEASDH
-- Execute este arquivo uma única vez no SQL Editor do Supabase.

create extension if not exists citext;

-- Perfis vinculados aos usuários do Supabase Auth.
create table if not exists public.profiles (
  id uuid primary key references auth.users(id) on delete cascade,
  username citext not null unique,
  first_name text not null,
  last_name text not null,
  department text not null,
  division text not null,
  job_title text not null,
  email citext not null unique,
  phone text not null,
  role text not null default 'USER' check (role in ('ADMIN', 'USER')),
  created_by_admin boolean not null default false,
  password_personalized boolean not null default true,
  active boolean not null default true,
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now()
);

-- Apenas o usuário maciel.soares recebe permissão administrativa.
create or replace function public.enforce_institutional_role()
returns trigger
language plpgsql
as $$
begin
  new.username := lower(trim(new.username));
  new.email := lower(trim(new.email));
  new.role := case when new.username = 'maciel.soares' then 'ADMIN' else 'USER' end;
  new.updated_at := now();
  return new;
end;
$$;

drop trigger if exists profiles_enforce_institutional_role on public.profiles;
create trigger profiles_enforce_institutional_role
before insert or update on public.profiles
for each row execute function public.enforce_institutional_role();

-- Cria o perfil automaticamente após um novo cadastro no Supabase Auth.
-- O frontend deve enviar estes dados em options.data no signUp.
create or replace function public.create_profile_for_new_user()
returns trigger
language plpgsql
security definer set search_path = public
as $$
begin
  insert into public.profiles (
    id, username, first_name, last_name, department, division,
    job_title, email, phone, created_by_admin, password_personalized
  ) values (
    new.id,
    coalesce(nullif(new.raw_user_meta_data->>'username', ''), split_part(new.email, '@', 1)),
    coalesce(nullif(new.raw_user_meta_data->>'first_name', ''), 'Usuário'),
    coalesce(nullif(new.raw_user_meta_data->>'last_name', ''), 'SEASDH'),
    coalesce(nullif(new.raw_user_meta_data->>'department', ''), 'Não informado'),
    coalesce(nullif(new.raw_user_meta_data->>'division', ''), 'Não informado'),
    coalesce(nullif(new.raw_user_meta_data->>'job_title', ''), 'Não informado'),
    new.email,
    coalesce(nullif(new.raw_user_meta_data->>'phone', ''), 'Não informado'),
    coalesce((new.raw_user_meta_data->>'created_by_admin')::boolean, false),
    not coalesce((new.raw_user_meta_data->>'created_by_admin')::boolean, false)
  );
  return new;
end;
$$;

drop trigger if exists auth_user_profile_created on auth.users;
create trigger auth_user_profile_created
after insert on auth.users
for each row execute function public.create_profile_for_new_user();

-- Eventos da agenda.
create table if not exists public.events (
  id uuid primary key default gen_random_uuid(),
  owner_id uuid not null default auth.uid() references public.profiles(id) on delete restrict,
  responsible text not null,
  department text not null,
  event_date date not null,
  event_time time not null,
  title text not null check (length(trim(title)) > 0),
  tag text,
  color text not null default '#027E28' check (color ~ '^#[0-9A-Fa-f]{6}$'),
  location text not null,
  description text,
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now()
);

create index if not exists events_event_date_time_idx on public.events (event_date, event_time);
create index if not exists events_owner_id_idx on public.events (owner_id);

-- Histórico automático das operações realizadas nos eventos.
create table if not exists public.audit_logs (
  id bigint generated always as identity primary key,
  actor_id uuid references public.profiles(id) on delete set null,
  action text not null check (action in ('CREATE', 'UPDATE', 'DELETE')),
  event_id uuid,
  event_title text not null,
  created_at timestamptz not null default now()
);

create index if not exists audit_logs_created_at_idx on public.audit_logs (created_at desc);

create or replace function public.audit_event_change()
returns trigger
language plpgsql
security definer set search_path = public
as $$
begin
  if tg_op = 'INSERT' then
    insert into public.audit_logs(actor_id, action, event_id, event_title)
    values (auth.uid(), 'CREATE', new.id, new.title);
    return new;
  elsif tg_op = 'UPDATE' then
    insert into public.audit_logs(actor_id, action, event_id, event_title)
    values (auth.uid(), 'UPDATE', new.id, new.title);
    return new;
  else
    insert into public.audit_logs(actor_id, action, event_id, event_title)
    values (auth.uid(), 'DELETE', old.id, old.title);
    return old;
  end if;
end;
$$;

drop trigger if exists events_audit_changes on public.events;
create trigger events_audit_changes
after insert or update or delete on public.events
for each row execute function public.audit_event_change();

-- Função segura para verificar se o usuário conectado é administrador.
create or replace function public.is_admin()
returns boolean
language sql
stable
security definer set search_path = public
as $$
  select exists (
    select 1 from public.profiles
    where id = auth.uid() and role = 'ADMIN'
  );
$$;

-- Atualiza updated_at também para eventos.
create or replace function public.set_updated_at()
returns trigger
language plpgsql
as $$
begin
  new.updated_at := now();
  return new;
end;
$$;

drop trigger if exists events_set_updated_at on public.events;
create trigger events_set_updated_at
before update on public.events
for each row execute function public.set_updated_at();

-- Segurança por linha (RLS).
alter table public.profiles enable row level security;
alter table public.events enable row level security;
alter table public.audit_logs enable row level security;

drop policy if exists "profiles: usuário lê o próprio perfil" on public.profiles;
create policy "profiles: usuário lê o próprio perfil"
on public.profiles for select to authenticated
using (id = auth.uid() or public.is_admin());

drop policy if exists "profiles: usuário altera o próprio perfil" on public.profiles;
create policy "profiles: usuário altera o próprio perfil"
on public.profiles for update to authenticated
using (id = auth.uid() or public.is_admin())
with check (id = auth.uid() or public.is_admin());

drop policy if exists "profiles: admin exclui perfis" on public.profiles;
create policy "profiles: admin exclui perfis"
on public.profiles for delete to authenticated
using (public.is_admin());

drop policy if exists "events: leitura para usuários autenticados" on public.events;
create policy "events: leitura para usuários autenticados"
on public.events for select to authenticated using (true);

drop policy if exists "events: usuário cria os próprios" on public.events;
create policy "events: usuário cria os próprios"
on public.events for insert to authenticated
with check (owner_id = auth.uid());

drop policy if exists "events: proprietário ou administrador atualiza" on public.events;
create policy "events: proprietário ou administrador atualiza"
on public.events for update to authenticated
using (owner_id = auth.uid() or public.is_admin())
with check (owner_id = auth.uid() or public.is_admin());

drop policy if exists "events: proprietário ou administrador exclui" on public.events;
create policy "events: proprietário ou administrador exclui"
on public.events for delete to authenticated
using (owner_id = auth.uid() or public.is_admin());

drop policy if exists "audit: usuário vê o próprio histórico" on public.audit_logs;
create policy "audit: usuário vê o próprio histórico"
on public.audit_logs for select to authenticated
using (actor_id = auth.uid() or public.is_admin());

-- A inserção no histórico é feita exclusivamente pelos gatilhos de eventos.

-- Função segura para administradores redefinirem senha de outros usuários no Supabase Auth
create or replace function public.admin_reset_password(target_user_id uuid, new_password text)
returns void
language plpgsql
security definer set search_path = public
as $$
begin
  if not public.is_admin() then
    raise exception 'Acesso negado: apenas administradores podem redefinir senhas.';
  end if;
  
  -- Atualiza a senha na tabela de autenticação interna do Supabase
  update auth.users
  set encrypted_password = crypt(new_password, gen_salt('bf')),
      raw_app_meta_data = raw_app_meta_data || jsonb_build_object('password_personalized', false)
  where id = target_user_id;

  -- Atualiza o estado da senha no perfil do usuário
  update public.profiles
  set password_personalized = false
  where id = target_user_id;
end;
$$;
