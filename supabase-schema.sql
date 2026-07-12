-- VM Agro - Supabase Auth, perfis, organizacoes, permissoes e RLS.
-- Execute este arquivo no SQL Editor do Supabase antes de publicar a nova versao.

create extension if not exists pgcrypto;

create table if not exists public.organizations (
  id uuid primary key default gen_random_uuid(),
  name text not null,
  slug text not null unique,
  active boolean not null default true,
  created_at timestamptz not null default now(),
  created_by uuid null references auth.users(id)
);

create table if not exists public.profiles (
  id uuid primary key references auth.users(id) on delete cascade,
  full_name text not null default '',
  email text not null default '',
  phone text,
  area text,
  avatar_url text,
  status text not null default 'pending' check (status in ('pending','active','blocked','rejected')),
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now(),
  last_login_at timestamptz,
  approved_at timestamptz,
  approved_by uuid references auth.users(id),
  blocked_at timestamptz,
  blocked_by uuid references auth.users(id)
);

create table if not exists public.organization_members (
  id uuid primary key default gen_random_uuid(),
  organization_id uuid not null references public.organizations(id) on delete cascade,
  user_id uuid not null references auth.users(id) on delete cascade,
  role text not null default 'viewer' check (role in ('master','admin','manager','editor','viewer','b3_operator')),
  active boolean not null default false,
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now(),
  invited_by uuid references auth.users(id),
  approved_by uuid references auth.users(id),
  unique (organization_id,user_id)
);

create table if not exists public.user_permissions (
  id uuid primary key default gen_random_uuid(),
  organization_id uuid not null references public.organizations(id) on delete cascade,
  user_id uuid not null references auth.users(id) on delete cascade,
  permission text not null,
  allowed boolean not null,
  created_at timestamptz not null default now(),
  created_by uuid references auth.users(id),
  unique (organization_id,user_id,permission)
);

create table if not exists public.audit_logs (
  id uuid primary key default gen_random_uuid(),
  organization_id uuid references public.organizations(id) on delete set null,
  user_id uuid references auth.users(id) on delete set null,
  action text not null,
  entity_type text,
  entity_id text,
  previous_data jsonb,
  new_data jsonb,
  created_at timestamptz not null default now(),
  ip inet,
  user_agent text
);

create table if not exists public.vm_agro_data (
  id uuid primary key default gen_random_uuid(),
  app_id text not null default 'vm-agro',
  user_key text not null,
  user_id uuid references auth.users(id) on delete set null,
  organization_id uuid references public.organizations(id) on delete cascade,
  key text not null,
  value jsonb not null default 'null'::jsonb,
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now(),
  unique (app_id,user_key,key)
);

alter table public.vm_agro_data add column if not exists organization_id uuid references public.organizations(id) on delete cascade;
alter table public.vm_agro_data add column if not exists user_id uuid references auth.users(id) on delete set null;

create index if not exists vm_agro_data_org_idx on public.vm_agro_data (organization_id,key);
create index if not exists organization_members_user_idx on public.organization_members (user_id,active);
create index if not exists audit_logs_org_created_idx on public.audit_logs (organization_id,created_at desc);

create or replace function public.vm_agro_touch_updated_at()
returns trigger language plpgsql as $$
begin new.updated_at=now(); return new; end;
$$;

drop trigger if exists vm_agro_data_touch_updated_at on public.vm_agro_data;
create trigger vm_agro_data_touch_updated_at before update on public.vm_agro_data
for each row execute function public.vm_agro_touch_updated_at();

drop trigger if exists profiles_touch_updated_at on public.profiles;
create trigger profiles_touch_updated_at before update on public.profiles
for each row execute function public.vm_agro_touch_updated_at();

drop trigger if exists organization_members_touch_updated_at on public.organization_members;
create trigger organization_members_touch_updated_at before update on public.organization_members
for each row execute function public.vm_agro_touch_updated_at();

create or replace function public.handle_new_auth_user()
returns trigger
language plpgsql
security definer set search_path=public
as $$
begin
  insert into public.profiles(id,full_name,email,phone,area,status)
  values(new.id,coalesce(new.raw_user_meta_data->>'full_name',''),lower(coalesce(new.email,'')),new.raw_user_meta_data->>'phone',new.raw_user_meta_data->>'area','pending')
  on conflict(id) do update set email=excluded.email,updated_at=now();
  insert into public.organization_members(organization_id,user_id,role,active)
  select o.id,new.id,'viewer',false from public.organizations o where o.slug='vm-agro'
  on conflict(organization_id,user_id) do nothing;
  return new;
end;
$$;

drop trigger if exists on_auth_user_created on auth.users;
create trigger on_auth_user_created after insert on auth.users
for each row execute function public.handle_new_auth_user();

create or replace function public.current_profile_active()
returns boolean language sql stable security definer set search_path=public as $$
  select exists(select 1 from public.profiles p where p.id=auth.uid() and p.status='active');
$$;

create or replace function public.is_org_member(org uuid)
returns boolean language sql stable security definer set search_path=public as $$
  select public.current_profile_active() and exists(
    select 1 from public.organization_members m
    where m.organization_id=org and m.user_id=auth.uid() and m.active
  );
$$;

create or replace function public.current_org_role(org uuid)
returns text language sql stable security definer set search_path=public as $$
  select m.role from public.organization_members m
  where m.organization_id=org and m.user_id=auth.uid() and m.active limit 1;
$$;

create or replace function public.is_org_admin(org uuid)
returns boolean language sql stable security definer set search_path=public as $$
  select public.current_org_role(org) in ('master','admin');
$$;

create or replace function public.has_org_permission(org uuid, permission_name text)
returns boolean language sql stable security definer set search_path=public as $$
  select exists(
    select 1 from public.user_permissions p
    where p.organization_id=org and p.user_id=auth.uid()
      and p.permission=permission_name and p.allowed
  );
$$;

create or replace function public.guard_last_master()
returns trigger language plpgsql security definer set search_path=public as $$
declare active_masters integer;
begin
  if old.role='master' and old.active and (tg_op='DELETE' or new.role<>'master' or not new.active) then
    select count(*) into active_masters from public.organization_members
    where organization_id=old.organization_id and role='master' and active and user_id<>old.user_id;
    if active_masters=0 then raise exception 'A organizacao deve manter pelo menos um Master ativo'; end if;
  end if;
  if tg_op='DELETE' then return old; end if;
  return new;
end;
$$;

drop trigger if exists protect_last_master on public.organization_members;
create trigger protect_last_master before update or delete on public.organization_members
for each row execute function public.guard_last_master();

alter table public.organizations enable row level security;
alter table public.profiles enable row level security;
alter table public.organization_members enable row level security;
alter table public.user_permissions enable row level security;
alter table public.audit_logs enable row level security;
alter table public.vm_agro_data enable row level security;

do $$ declare r record; begin
  for r in select schemaname,tablename,policyname from pg_policies
    where schemaname='public' and tablename in ('organizations','profiles','organization_members','user_permissions','audit_logs','vm_agro_data')
  loop execute format('drop policy if exists %I on %I.%I',r.policyname,r.schemaname,r.tablename); end loop;
end $$;

create policy organizations_select_member on public.organizations for select to authenticated
using (public.is_org_member(id));

create policy profiles_select_self_or_admin on public.profiles for select to authenticated
using (id=auth.uid() or exists(
  select 1 from public.organization_members me join public.organization_members target
    on target.organization_id=me.organization_id
  where me.user_id=auth.uid() and me.active and me.role in ('master','admin') and target.user_id=profiles.id
));

create or replace function public.touch_last_login()
returns void language sql security definer set search_path=public as $$
  update public.profiles set last_login_at=now() where id=auth.uid();
$$;

revoke all on function public.touch_last_login() from public;
grant execute on function public.touch_last_login() to authenticated;

create policy members_select_same_org on public.organization_members for select to authenticated
using (public.is_org_member(organization_id));

create policy permissions_select_own_or_admin on public.user_permissions for select to authenticated
using (user_id=auth.uid() or public.is_org_admin(organization_id));

create policy audit_select_admin on public.audit_logs for select to authenticated
using (public.is_org_admin(organization_id));

create policy audit_insert_member on public.audit_logs for insert to authenticated
with check (user_id=auth.uid() and public.is_org_member(organization_id));

create policy data_select_member on public.vm_agro_data for select to authenticated
using (public.is_org_member(organization_id));

create policy data_insert_editor on public.vm_agro_data for insert to authenticated
with check (
  public.current_org_role(organization_id) in ('master','admin')
  or (public.current_org_role(organization_id) in ('manager','editor') and key='lotes')
  or ((public.current_org_role(organization_id)='b3_operator' or public.has_org_permission(organization_id,'b3.create') or public.has_org_permission(organization_id,'b3.edit')) and key='futuros')
);

create policy data_update_editor on public.vm_agro_data for update to authenticated
using (
  public.current_org_role(organization_id) in ('master','admin')
  or (public.current_org_role(organization_id) in ('manager','editor') and key='lotes')
  or ((public.current_org_role(organization_id)='b3_operator' or public.has_org_permission(organization_id,'b3.create') or public.has_org_permission(organization_id,'b3.edit')) and key='futuros')
)
with check (
  public.current_org_role(organization_id) in ('master','admin')
  or (public.current_org_role(organization_id) in ('manager','editor') and key='lotes')
  or ((public.current_org_role(organization_id)='b3_operator' or public.has_org_permission(organization_id,'b3.create') or public.has_org_permission(organization_id,'b3.edit')) and key='futuros')
);

create policy data_delete_admin on public.vm_agro_data for delete to authenticated
using (public.current_org_role(organization_id) in ('master','admin'));

-- Cria a organizacao inicial. Depois de criar o primeiro usuario no Auth,
-- execute o bloco comentado abaixo substituindo o e-mail.
insert into public.organizations(name,slug,active)
values('VM Agro','vm-agro',true)
on conflict(slug) do nothing;

-- PRIMEIRO MASTER (execute uma vez, apos cadastrar o proprietario no Auth):
-- update public.profiles set status='active',approved_at=now()
-- where email='SEU_EMAIL_MASTER';
-- insert into public.organization_members(organization_id,user_id,role,active,approved_by)
-- select o.id,p.id,'master',true,p.id from public.organizations o,public.profiles p
-- where o.slug='vm-agro' and p.email='SEU_EMAIL_MASTER'
-- on conflict(organization_id,user_id) do update set role='master',active=true;

-- MIGRACAO DOS DADOS JSON EXISTENTES PARA A ORGANIZACAO VM AGRO:
-- update public.vm_agro_data d set organization_id=o.id,user_key=o.id::text
-- from public.organizations o where o.slug='vm-agro' and d.organization_id is null;

grant execute on function public.current_profile_active() to authenticated;
grant execute on function public.is_org_member(uuid) to authenticated;
grant execute on function public.current_org_role(uuid) to authenticated;
grant execute on function public.is_org_admin(uuid) to authenticated;
grant execute on function public.has_org_permission(uuid,text) to authenticated;
