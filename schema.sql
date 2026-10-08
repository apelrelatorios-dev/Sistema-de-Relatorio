-- ============================================================
-- STTP Relatórios — schema do Supabase (PostgreSQL)
-- Cole no Supabase: SQL Editor -> New query -> Run
-- Pode rodar mais de uma vez (não apaga dados existentes).
-- ============================================================

-- 1) PERFIS (um por usuário do Authentication) ----------------
create table if not exists public.profiles (
  id uuid primary key references auth.users(id) on delete cascade,
  username text,
  is_admin boolean not null default false,
  can_create_reports boolean not null default true,
  can_edit_reports boolean not null default false,
  can_delete_reports boolean not null default false,
  can_edit_settings boolean not null default false,
  created_at timestamptz not null default now()
);

-- cria o perfil automaticamente quando um usuário é criado
create or replace function public.handle_new_user()
returns trigger language plpgsql security definer set search_path = public as $$
begin
  insert into public.profiles (id, username)
  values (new.id, split_part(new.email, '@', 1))
  on conflict (id) do nothing;
  return new;
end $$;

drop trigger if exists on_auth_user_created on auth.users;
create trigger on_auth_user_created
  after insert on auth.users
  for each row execute function public.handle_new_user();

-- perfis de usuários que já existiam
insert into public.profiles (id, username)
select id, split_part(email, '@', 1) from auth.users
on conflict (id) do nothing;

create or replace function public.is_admin()
returns boolean language sql stable security definer set search_path = public as $$
  select coalesce((select is_admin from public.profiles where id = auth.uid()), false)
$$;

-- 2) RELATÓRIOS ------------------------------------------------
create table if not exists public.reports (
  id uuid primary key default gen_random_uuid(),
  contrato text not null default '',
  data date not null,
  hora_chegada text not null default '',
  hora_saida text not null default '',
  tecnico text not null,
  tipo_manutencao jsonb not null default '[]'::jsonb,
  sistema_key text not null default '',
  sistema_label text not null default '',
  items jsonb not null default '[]'::jsonb,
  locais jsonb not null default '[]'::jsonb,
  checklist jsonb not null default '{}'::jsonb,
  observacoes text not null default '',
  visto_tecnico text not null default '',
  visto_cliente text not null default '',
  fotos jsonb not null default '[]'::jsonb,
  created_by uuid references auth.users(id) on delete set null,
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now()
);
alter table public.reports add column if not exists fotos jsonb not null default '[]'::jsonb;

create or replace function public.touch_updated_at()
returns trigger language plpgsql as $$
begin new.updated_at = now(); return new; end $$;

drop trigger if exists reports_touch on public.reports;
create trigger reports_touch before update on public.reports
  for each row execute function public.touch_updated_at();

-- 3) CONFIGURAÇÕES (logos, identificação) ----------------------
create table if not exists public.settings (
  key text primary key,
  value text
);

-- 4) HISTÓRICO DE ALTERAÇÕES ----------------------------------
create table if not exists public.report_audit_log (
  id bigint generated always as identity primary key,
  report_id uuid,
  action text not null,
  old_data jsonb,
  new_data jsonb,
  changed_by uuid,
  changed_by_email text,
  changed_at timestamptz not null default now()
);

create or replace function public.log_report_change()
returns trigger language plpgsql security definer set search_path = public as $$
declare v_email text;
begin
  select email into v_email from auth.users where id = auth.uid();
  if tg_op = 'DELETE' then
    insert into public.report_audit_log (report_id, action, old_data, changed_by, changed_by_email)
    values (old.id, 'delete', to_jsonb(old), auth.uid(), v_email);
    return old;
  else
    insert into public.report_audit_log (report_id, action, old_data, new_data, changed_by, changed_by_email)
    values (new.id, 'update', to_jsonb(old), to_jsonb(new), auth.uid(), v_email);
    return new;
  end if;
end $$;

drop trigger if exists reports_audit on public.reports;
create trigger reports_audit after update or delete on public.reports
  for each row execute function public.log_report_change();

-- 5) PARECERES TÉCNICOS ---------------------------------------
create table if not exists public.pareceres_tecnicos (
  id uuid primary key default gen_random_uuid(),
  cidade text not null default '',
  data_documento date,
  referencia text not null default '',
  cliente_nome text not null,
  cliente_cnpj text not null default '',
  equipamento_descricao text not null default '',
  objetivo text not null default '',
  procedimento_intro text not null default '',
  procedimento_testes jsonb not null default '[]'::jsonb,
  componentes jsonb not null default '[]'::jsonb,
  observacao_intro text not null default '',
  observacao_itens jsonb not null default '[]'::jsonb,
  responsavel_tecnico text not null default '',
  created_by uuid references auth.users(id) on delete set null,
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now()
);

-- 6) SEGURANÇA (RLS) ------------------------------------------
alter table public.profiles           enable row level security;
alter table public.reports            enable row level security;
alter table public.settings           enable row level security;
alter table public.report_audit_log   enable row level security;
alter table public.pareceres_tecnicos enable row level security;

drop policy if exists "profiles_select" on public.profiles;
create policy "profiles_select" on public.profiles for select to authenticated using (true);
drop policy if exists "profiles_update_admin" on public.profiles;
create policy "profiles_update_admin" on public.profiles for update to authenticated
  using (public.is_admin()) with check (public.is_admin());

drop policy if exists "reports_all" on public.reports;
create policy "reports_all" on public.reports for all to authenticated using (true) with check (true);

drop policy if exists "pareceres_all" on public.pareceres_tecnicos;
create policy "pareceres_all" on public.pareceres_tecnicos for all to authenticated using (true) with check (true);

-- logos aparecem na tela de login, então leitura é pública
drop policy if exists "settings_select" on public.settings;
create policy "settings_select" on public.settings for select to anon, authenticated using (true);
drop policy if exists "settings_write" on public.settings;
create policy "settings_write" on public.settings for all to authenticated using (true) with check (true);

drop policy if exists "audit_select" on public.report_audit_log;
create policy "audit_select" on public.report_audit_log for select to authenticated using (true);

-- 7) STORAGE DAS FOTOS ----------------------------------------
insert into storage.buckets (id, name, public)
values ('fotos-relatorios', 'fotos-relatorios', true)
on conflict (id) do nothing;

drop policy if exists "Autenticados podem enviar fotos" on storage.objects;
create policy "Autenticados podem enviar fotos" on storage.objects for insert
  with check (bucket_id = 'fotos-relatorios' and auth.role() = 'authenticated');
drop policy if exists "Autenticados podem excluir fotos" on storage.objects;
create policy "Autenticados podem excluir fotos" on storage.objects for delete
  using (bucket_id = 'fotos-relatorios' and auth.role() = 'authenticated');
drop policy if exists "Qualquer um pode ver as fotos" on storage.objects;
create policy "Qualquer um pode ver as fotos" on storage.objects for select
  using (bucket_id = 'fotos-relatorios');

-- 8) TORNE-SE ADMIN (troque pelo seu e-mail e rode separado) ---
-- update public.profiles set is_admin = true
-- where id = (select id from auth.users where email = 'seu@email.com');
