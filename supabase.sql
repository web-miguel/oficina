-- Mi oficina · esquema Supabase
-- La copia se guarda YA CIFRADA en el navegador (AES-GCM + ECDH). Supabase solo guarda el sobre cifrado:
-- nunca recibe los datos en claro ni la clave que los abre.
-- Todo cambio pasa por funciones (RPC); las tablas no aceptan escrituras directas.

create table if not exists public.oficinas (
  id              uuid primary key default gen_random_uuid(),
  sobre           text not null,
  version         bigint not null default 1,
  actualizado     timestamptz not null default now(),
  actualizado_por uuid references auth.users(id) on delete set null,
  creada          timestamptz not null default now()
);

create table if not exists public.miembros (
  oficina_id uuid not null references public.oficinas(id) on delete cascade,
  user_id    uuid not null references auth.users(id) on delete cascade,
  usuario    text not null,
  agregado   timestamptz not null default now(),
  primary key (oficina_id, user_id),
  unique (oficina_id, usuario)
);

create table if not exists public.copias (
  id         bigint generated always as identity primary key,
  oficina_id uuid not null references public.oficinas(id) on delete cascade,
  sobre      text not null,
  version    bigint not null,
  creada     timestamptz not null default now(),
  creada_por uuid references auth.users(id) on delete set null,
  motivo     text not null default 'diaria'
);
create index if not exists copias_oficina_creada on public.copias (oficina_id, creada desc);

alter table public.oficinas enable row level security;
alter table public.miembros enable row level security;
alter table public.copias   enable row level security;
revoke all on public.oficinas, public.miembros, public.copias from anon, authenticated;

-- Copias que se conservan (diarias + manuales + antes de restaurar).
create or replace function public._podar_copias(p_oficina uuid) returns void
language sql security definer set search_path = public as $$
  delete from copias where oficina_id = p_oficina and id not in (
    select id from copias where oficina_id = p_oficina order by creada desc limit 30);
$$;

create or replace function public._es_miembro(p_oficina uuid) returns boolean
language sql stable security definer set search_path = public as $$
  select exists (select 1 from miembros where oficina_id = p_oficina and user_id = auth.uid());
$$;

-- Oficina del usuario que entra (con su nombre de usuario dentro de la copia).
create or replace function public.abrir_oficina()
returns table (id uuid, sobre text, version bigint, actualizado timestamptz, usuario text)
language sql stable security definer set search_path = public as $$
  select o.id, o.sobre, o.version, o.actualizado, m.usuario
  from oficinas o join miembros m on m.oficina_id = o.id
  where m.user_id = auth.uid()
  order by m.agregado limit 1;
$$;

-- Primera subida: solo se permite si aún no existe ninguna oficina (instalación de una sola oficina).
create or replace function public.crear_oficina(p_sobre text, p_usuario text) returns uuid
language plpgsql security definer set search_path = public as $$
declare v_id uuid;
begin
  if auth.uid() is null then raise exception 'Sin sesión'; end if;
  perform pg_advisory_xact_lock(hashtext('mi-oficina-crear'));
  if exists (select 1 from oficinas) then
    raise exception 'Ya existe una oficina. Pide a un usuario que te agregue.' using errcode = 'P0001';
  end if;
  insert into oficinas (sobre, actualizado_por) values (p_sobre, auth.uid()) returning id into v_id;
  insert into miembros (oficina_id, user_id, usuario) values (v_id, auth.uid(), p_usuario);
  insert into copias (oficina_id, sobre, version, creada_por, motivo) values (v_id, p_sobre, 1, auth.uid(), 'primera subida');
  return v_id;
end $$;

-- Guardado con control de versión: si otro guardó antes, devuelve -1 y no sobrescribe.
-- La primera vez de cada día (hora Colombia) guarda una copia de la versión anterior.
create or replace function public.guardar_oficina(p_id uuid, p_sobre text, p_version bigint, p_motivo text default null)
returns bigint
language plpgsql security definer set search_path = public as $$
declare o oficinas%rowtype;
begin
  if not _es_miembro(p_id) then raise exception 'Sin acceso a esta oficina' using errcode = '42501'; end if;
  select * into o from oficinas where id = p_id for update;
  if o.version <> p_version then return -1; end if;
  if p_motivo is not null or not exists (
    select 1 from copias where oficina_id = p_id
      and (creada at time zone 'America/Bogota')::date = (now() at time zone 'America/Bogota')::date) then
    insert into copias (oficina_id, sobre, version, creada_por, motivo)
    values (p_id, o.sobre, o.version, auth.uid(), coalesce(p_motivo, 'diaria'));
    perform _podar_copias(p_id);
  end if;
  update oficinas set sobre = p_sobre, version = o.version + 1, actualizado = now(), actualizado_por = auth.uid()
  where id = p_id;
  return o.version + 1;
end $$;

-- Copia manual de la versión actual (botón Guardar copia).
create or replace function public.copia_manual(p_id uuid) returns timestamptz
language plpgsql security definer set search_path = public as $$
declare v timestamptz;
begin
  if not _es_miembro(p_id) then raise exception 'Sin acceso a esta oficina' using errcode = '42501'; end if;
  insert into copias (oficina_id, sobre, version, creada_por, motivo)
  select id, sobre, version, auth.uid(), 'manual' from oficinas where id = p_id returning creada into v;
  perform _podar_copias(p_id);
  return v;
end $$;

create or replace function public.listar_copias(p_id uuid)
returns table (id bigint, creada timestamptz, version bigint, motivo text, usuario text, tamano int)
language sql stable security definer set search_path = public as $$
  select c.id, c.creada, c.version, c.motivo, m.usuario, length(c.sobre)
  from copias c left join miembros m on m.oficina_id = c.oficina_id and m.user_id = c.creada_por
  where c.oficina_id = p_id and _es_miembro(p_id)
  order by c.creada desc;
$$;

create or replace function public.leer_copia(p_copia bigint) returns text
language sql stable security definer set search_path = public as $$
  select sobre from copias where id = p_copia and _es_miembro(oficina_id);
$$;

-- Restaurar: la versión actual queda guardada como copia antes de reemplazarla.
create or replace function public.restaurar_copia(p_copia bigint) returns bigint
language plpgsql security definer set search_path = public as $$
declare c copias%rowtype; o oficinas%rowtype;
begin
  select * into c from copias where id = p_copia;
  if c.id is null or not _es_miembro(c.oficina_id) then raise exception 'Sin acceso' using errcode = '42501'; end if;
  select * into o from oficinas where id = c.oficina_id for update;
  insert into copias (oficina_id, sobre, version, creada_por, motivo) values (o.id, o.sobre, o.version, auth.uid(), 'antes de restaurar');
  update oficinas set sobre = c.sobre, version = o.version + 1, actualizado = now(), actualizado_por = auth.uid() where id = o.id;
  perform _podar_copias(o.id);
  return o.version + 1;
end $$;

-- Usuarios: el acceso a la nube sigue a la lista de usuarios de la copia.
create or replace function public.agregar_miembro(p_id uuid, p_correo text, p_usuario text) returns void
language plpgsql security definer set search_path = public, auth as $$
declare v_uid uuid;
begin
  if not _es_miembro(p_id) then raise exception 'Sin acceso a esta oficina' using errcode = '42501'; end if;
  select u.id into v_uid from auth.users u where lower(u.email) = lower(trim(p_correo));
  if v_uid is null then raise exception 'No hay una cuenta con ese correo.' using errcode = 'P0001'; end if;
  insert into miembros (oficina_id, user_id, usuario) values (p_id, v_uid, p_usuario)
  on conflict (oficina_id, user_id) do update set usuario = excluded.usuario;
end $$;

create or replace function public.quitar_miembro(p_id uuid, p_usuario text) returns void
language plpgsql security definer set search_path = public as $$
begin
  if not _es_miembro(p_id) then raise exception 'Sin acceso a esta oficina' using errcode = '42501'; end if;
  delete from miembros where oficina_id = p_id and usuario = p_usuario and user_id <> auth.uid();
end $$;

create or replace function public.renombrar_miembro(p_id uuid, p_usuario text) returns void
language sql security definer set search_path = public as $$
  update miembros set usuario = p_usuario where oficina_id = p_id and user_id = auth.uid();
$$;

revoke all on function public._podar_copias(uuid), public._es_miembro(uuid) from public, anon, authenticated;
revoke all on function public.abrir_oficina(), public.crear_oficina(text, text), public.guardar_oficina(uuid, text, bigint, text),
  public.copia_manual(uuid), public.listar_copias(uuid), public.leer_copia(bigint), public.restaurar_copia(bigint),
  public.agregar_miembro(uuid, text, text), public.quitar_miembro(uuid, text), public.renombrar_miembro(uuid, text) from public, anon;
grant execute on function public.abrir_oficina(), public.crear_oficina(text, text), public.guardar_oficina(uuid, text, bigint, text),
  public.copia_manual(uuid), public.listar_copias(uuid), public.leer_copia(bigint), public.restaurar_copia(bigint),
  public.agregar_miembro(uuid, text, text), public.quitar_miembro(uuid, text), public.renombrar_miembro(uuid, text) to authenticated;
