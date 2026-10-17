-- ========================================================
-- 1. ESQUEMA DE TABLAS PRINCIPALES (Base)
-- ========================================================

create table perfiles (
  id uuid primary key references auth.users on delete cascade,
  nombre text,
  rol text not null default 'usuario' check (rol in ('usuario', 'admin', 'superadmin'))
);

create table salones (
  id uuid primary key default gen_random_uuid(),
  nombre text not null,
  descripcion text,
  direccion text,
  capacidad int,
  precio numeric,
  imagen_principal text,
  activo boolean default true,
  created_at timestamptz default now()
);

create table salon_imagenes (
  id uuid primary key default gen_random_uuid(),
  salon_id uuid references salones on delete cascade,
  url text not null,
  orden int default 0
);

create table resenas (
  id uuid primary key default gen_random_uuid(),
  salon_id uuid references salones on delete cascade,
  user_id uuid references auth.users on delete cascade,
  puntaje int not null check (puntaje between 1 and 5),
  comentario text,
  created_at timestamptz default now()
);

create table reservas (
  id uuid primary key default gen_random_uuid(),
  salon_id uuid references salones on delete cascade,
  user_id uuid references auth.users on delete cascade,
  fecha date not null,
  estado text not null default 'pendiente' check (estado in ('pendiente', 'confirmada', 'cancelada')),
  created_at timestamptz default now()
);

create unique index reservas_unica on reservas (salon_id, fecha) where estado <> 'cancelada';

create table admin_salones (
  admin_id uuid references perfiles on delete cascade,
  salon_id uuid references salones on delete cascade,
  primary key (admin_id, salon_id)
);

-- Trigger para crear el perfil automático al registrarse un usuario
create or replace function crear_perfil() returns trigger language plpgsql security definer as $$
begin
  insert into perfiles (id, nombre) values (new.id, coalesce(new.raw_user_meta_data->>'nombre', split_part(new.email,'@',1)));
  return new;
end; $$;

create trigger on_auth_user_created after insert on auth.users for each row execute function crear_perfil();


-- ========================================================
-- 2. ROLES, FUNCIONES Y POLÍTICAS RLS 
-- ========================================================

-- Helpers de rol
create or replace function es_superadmin() returns boolean language sql security definer stable as $$
  select exists (select 1 from perfiles where id = auth.uid() and rol = 'superadmin');
$$;

create or replace function es_admin_de(p_salon uuid) returns boolean language sql security definer stable as $$
  select es_superadmin() or exists (
    select 1 from admin_salones a join perfiles p on p.id = a.admin_id
    where a.admin_id = auth.uid() and a.salon_id = p_salon and p.rol = 'admin'
  );
$$;

-- Máximo 4 administradores
create or replace function limitar_admins() returns trigger language plpgsql as $$
begin
  if new.rol = 'admin' and (select count(*) from perfiles where rol = 'admin' and id <> new.id) >= 4 then
    raise exception 'Máximo 4 administradores';
  end if;
  return new;
end; $$;

create trigger trg_limitar_admins before insert or update on perfiles 
for each row execute function limitar_admins();

-- Agregar / quitar admin
create or replace function asignar_admin(p_email text) returns void language plpgsql security definer as $$
declare uid uuid;
begin
  if not es_superadmin() then raise exception 'No autorizado'; end if;
  select id into uid from auth.users where email = p_email;
  if uid is null then raise exception 'El usuario no existe (debe registrarse primero)'; end if;
  update perfiles set rol = 'admin' where id = uid;
end; $$;

create or replace function quitar_admin(p_id uuid) returns void language plpgsql security definer as $$
begin
  if not es_superadmin() then raise exception 'No autorizado'; end if;
  delete from admin_salones where admin_id = p_id;
  update perfiles set rol = 'usuario' where id = p_id and rol = 'admin';
end; $$;

-- Habilitar RLS
alter table perfiles enable row level security;
alter table salones enable row level security;
alter table salon_imagenes enable row level security;
alter table resenas enable row level security;
alter table reservas enable row level security;
alter table admin_salones enable row level security;

-- Políticas RLS
create policy salones_ver on salones for select using (true);
create policy imgs_ver on salon_imagenes for select using (true);
create policy resenas_ver on resenas for select using (true);

create policy resenas_crear on resenas for insert to authenticated with check (user_id = auth.uid());

create policy salones_editar on salones for update to authenticated using (es_admin_de(id));
create policy salones_crear on salones for insert to authenticated with check (es_superadmin());
create policy imgs_gestionar on salon_imagenes for all to authenticated using (es_admin_de(salon_id)) with check (es_admin_de(salon_id));

create policy reservas_ver on reservas for select to authenticated using (user_id = auth.uid() or es_admin_de(salon_id));
create policy reservas_crear on reservas for insert to authenticated with check (user_id = auth.uid());
create policy reservas_gestionar on reservas for update to authenticated using (es_admin_de(salon_id));

create policy perfiles_ver on perfiles for select to authenticated using (id = auth.uid() or es_superadmin());
create policy as_ver on admin_salones for select to authenticated using (admin_id = auth.uid() or es_superadmin());
create policy as_gestionar on admin_salones for all to authenticated using (es_superadmin()) with check (es_superadmin());