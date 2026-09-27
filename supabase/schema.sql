-- Дневник ДЗ: база данных Supabase.
-- Выполни этот файл один раз: Supabase → SQL Editor → New query → вставь всё → Run.
-- Повторный запуск безопасен: существующие данные не удаляются.

create extension if not exists pgcrypto with schema extensions;

-- ---------- таблицы ----------

-- Ученики. Строка создаётся сама при регистрации (см. триггер ниже).
create table if not exists public.profiles (
  id uuid primary key references auth.users(id) on delete cascade,
  name text not null check (char_length(name) between 2 and 40),
  is_admin boolean not null default false,
  created_at timestamptz not null default now()
);
create unique index if not exists profiles_name_lower on public.profiles (lower(name));

-- Настройки класса. Код класса видит только администратор.
create table if not exists public.app_config (
  id int primary key default 1 check (id = 1),
  invite_code text
);
insert into public.app_config (id) values (1) on conflict (id) do nothing;

-- Общее расписание класса (одна строка).
create table if not exists public.class_schedule (
  id int primary key default 1 check (id = 1),
  data jsonb not null,
  updated_at timestamptz not null default now(),
  updated_by uuid default auth.uid()
);

-- Домашние задания, общие для класса.
create table if not exists public.homeworks (
  id text primary key check (id ~ '^[A-Za-z0-9_-]{4,40}$'),
  subject_id text not null,
  due date not null,
  text text not null default '' check (char_length(text) <= 4000),
  photos text[] not null default '{}',
  author uuid default auth.uid() references public.profiles(id) on delete set null,
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now(),
  updated_by uuid default auth.uid()
);
create index if not exists homeworks_due on public.homeworks (due);

-- Личное у каждого: отметки «Выполнено», план, тема, напоминание.
create table if not exists public.prefs (
  user_id uuid primary key default auth.uid() references public.profiles(id) on delete cascade,
  data jsonb not null default '{}',
  updated_at timestamptz not null default now()
);

-- ---------- регистрация ----------

create or replace function public.handle_new_user() returns trigger
language plpgsql security definer set search_path = public as $$
declare
  v_name text := btrim(regexp_replace(coalesce(new.raw_user_meta_data->>'name', ''), '\s+', ' ', 'g'));
  v_code text;
begin
  if char_length(v_name) < 2 or char_length(v_name) > 40 then
    raise exception 'DNEVNIK_BAD_NAME';
  end if;
  select invite_code into v_code from public.app_config where id = 1;
  if coalesce(v_code, '') <> '' and coalesce(new.raw_user_meta_data->>'invite', '') <> v_code then
    raise exception 'DNEVNIK_BAD_INVITE';
  end if;
  -- первый зарегистрированный становится администратором
  insert into public.profiles (id, name, is_admin)
  values (new.id, v_name, not exists (select 1 from public.profiles));
  return new;
end $$;
revoke execute on function public.handle_new_user() from public, anon, authenticated;

drop trigger if exists on_auth_user_created on auth.users;
create trigger on_auth_user_created after insert on auth.users
  for each row execute function public.handle_new_user();

-- Автор задания не меняется при правке; фиксируем, кто и когда правил.
create or replace function public.homeworks_touch() returns trigger
language plpgsql set search_path = public as $$
begin
  if tg_op = 'UPDATE' then
    new.author := old.author;
    new.created_at := old.created_at;
  end if;
  new.updated_at := now();
  new.updated_by := auth.uid();
  return new;
end $$;
drop trigger if exists homeworks_touch on public.homeworks;
create trigger homeworks_touch before insert or update on public.homeworks
  for each row execute function public.homeworks_touch();

-- ---------- права доступа (RLS) ----------

create or replace function public.is_admin() returns boolean
language sql stable security definer set search_path = public as $$
  select coalesce((select is_admin from public.profiles where id = auth.uid()), false);
$$;

alter table public.profiles enable row level security;
alter table public.app_config enable row level security;
alter table public.class_schedule enable row level security;
alter table public.homeworks enable row level security;
alter table public.prefs enable row level security;

drop policy if exists "profiles: ученики видят имена" on public.profiles;
create policy "profiles: ученики видят имена" on public.profiles for select to authenticated using (true);

drop policy if exists "app_config: только админ" on public.app_config;
create policy "app_config: только админ" on public.app_config for select to authenticated using (public.is_admin());

drop policy if exists "schedule: читают ученики" on public.class_schedule;
create policy "schedule: читают ученики" on public.class_schedule for select to authenticated using (true);
drop policy if exists "schedule: меняют ученики" on public.class_schedule;
create policy "schedule: меняют ученики" on public.class_schedule for update to authenticated using (true) with check (id = 1);

drop policy if exists "homeworks: читают ученики" on public.homeworks;
create policy "homeworks: читают ученики" on public.homeworks for select to authenticated using (true);
drop policy if exists "homeworks: добавляют от своего имени" on public.homeworks;
create policy "homeworks: добавляют от своего имени" on public.homeworks for insert to authenticated with check (author = auth.uid());
drop policy if exists "homeworks: правят ученики" on public.homeworks;
create policy "homeworks: правят ученики" on public.homeworks for update to authenticated using (true) with check (true);
drop policy if exists "homeworks: удаляют ученики" on public.homeworks;
create policy "homeworks: удаляют ученики" on public.homeworks for delete to authenticated using (true);

drop policy if exists "prefs: только свои" on public.prefs;
create policy "prefs: только свои" on public.prefs for all to authenticated
  using (user_id = auth.uid()) with check (user_id = auth.uid());

-- ---------- действия администратора ----------

create or replace function public.admin_reset_password(p_user uuid) returns text
language plpgsql security definer set search_path = public, extensions as $$
declare v_pass text := lpad(floor(random() * 1000000)::int::text, 6, '0');
begin
  if not public.is_admin() then raise exception 'DNEVNIK_NOT_ADMIN'; end if;
  if not exists (select 1 from public.profiles where id = p_user) then raise exception 'DNEVNIK_NO_USER'; end if;
  update auth.users set encrypted_password = extensions.crypt(v_pass, extensions.gen_salt('bf')), updated_at = now()
  where id = p_user;
  delete from auth.sessions where user_id = p_user;
  return v_pass;
end $$;

create or replace function public.admin_clear_old(p_before date) returns text[]
language plpgsql security definer set search_path = public as $$
declare v_photos text[];
begin
  if not public.is_admin() then raise exception 'DNEVNIK_NOT_ADMIN'; end if;
  with gone as (delete from public.homeworks where due < p_before returning photos)
  select coalesce(array_agg(p), '{}') into v_photos from gone, unnest(gone.photos) as p;
  return v_photos;
end $$;

create or replace function public.admin_wipe() returns void
language plpgsql security definer set search_path = public as $$
begin
  if not public.is_admin() then raise exception 'DNEVNIK_NOT_ADMIN'; end if;
  delete from public.homeworks where true;
  update public.class_schedule
    set data = jsonb_build_object('subjects', '[]'::jsonb, 'lessons', '[]'::jsonb, 'bells', data->'bells'), updated_at = now()
    where id = 1;
  update public.prefs set data = data - 'done' - 'plan' where true;
end $$;

create or replace function public.admin_set_invite(p_code text) returns void
language plpgsql security definer set search_path = public as $$
begin
  if not public.is_admin() then raise exception 'DNEVNIK_NOT_ADMIN'; end if;
  update public.app_config set invite_code = nullif(btrim(p_code), '') where id = 1;
end $$;

create or replace function public.delete_my_account() returns void
language plpgsql security definer set search_path = public as $$
begin
  if auth.uid() is null then raise exception 'DNEVNIK_NOT_SIGNED_IN'; end if;
  delete from auth.users where id = auth.uid();
end $$;

revoke execute on function public.admin_reset_password(uuid), public.admin_clear_old(date), public.admin_wipe(),
  public.admin_set_invite(text), public.delete_my_account() from public, anon;
grant execute on function public.admin_reset_password(uuid), public.admin_clear_old(date), public.admin_wipe(),
  public.admin_set_invite(text), public.delete_my_account() to authenticated;

-- ---------- фото заданий (закрытое хранилище) ----------

insert into storage.buckets (id, name, public, file_size_limit, allowed_mime_types)
values ('photos', 'photos', false, 3145728, array['image/jpeg'])
on conflict (id) do nothing;

drop policy if exists "photos: смотрят ученики" on storage.objects;
create policy "photos: смотрят ученики" on storage.objects for select to authenticated using (bucket_id = 'photos');
drop policy if exists "photos: загружают ученики" on storage.objects;
create policy "photos: загружают ученики" on storage.objects for insert to authenticated with check (bucket_id = 'photos');
drop policy if exists "photos: заменяют ученики" on storage.objects;
create policy "photos: заменяют ученики" on storage.objects for update to authenticated using (bucket_id = 'photos');
drop policy if exists "photos: удаляют ученики" on storage.objects;
create policy "photos: удаляют ученики" on storage.objects for delete to authenticated using (bucket_id = 'photos');

-- ---------- обновления в реальном времени ----------

do $$
declare t text;
begin
  foreach t in array array['homeworks', 'class_schedule', 'profiles'] loop
    begin
      execute format('alter publication supabase_realtime add table public.%I', t);
    exception when duplicate_object then null;
    end;
  end loop;
end $$;

-- ---------- расписание 11б ----------
-- period = номер урока; пропуск (суббота, 1-й урок) = просто нет строки.

insert into public.class_schedule (id, data) values (1, $json${"subjects":[{"id":"s001","name":"Разговоры о важном","color":"#4A74E0"},{"id":"s003","name":"История","color":"#2E9E77"},{"id":"s005","name":"География","color":"#D08A2E"},{"id":"s007","name":"Вероятность и статистика","color":"#D0584F"},{"id":"s009","name":"Русский язык","color":"#7B68D8"},{"id":"s00c","name":"Физика","color":"#2A9DB0"},{"id":"s00f","name":"Биология","color":"#B0569E"},{"id":"s00h","name":"Физкультура","color":"#5E8A3A"},{"id":"s00j","name":"Алгебра","color":"#C2703D"},{"id":"s00m","name":"Фил. проблемы современности","color":"#5872B8"},{"id":"s00q","name":"Литература","color":"#4A74E0"},{"id":"s00u","name":"Геометрия","color":"#2E9E77"},{"id":"s00x","name":"Информатика","color":"#D08A2E"},{"id":"s010","name":"Обществознание","color":"#D0584F"},{"id":"s014","name":"Смысловой лингв. анализ","color":"#7B68D8"},{"id":"s016","name":"Немецкий язык","color":"#2A9DB0"},{"id":"s019","name":"Дискуссионные вопросы истории","color":"#B0569E"},{"id":"s01e","name":"ОБЗР","color":"#5E8A3A"},{"id":"s01h","name":"Английский язык","color":"#C2703D"},{"id":"s01j","name":"Химия","color":"#5872B8"},{"id":"s01l","name":"Немецкий язык / Информатика","color":"#4A74E0"},{"id":"s01n","name":"Избранные вопросы математики","color":"#2E9E77"}],"lessons":[{"id":"l002","weekday":1,"period":1,"subjectId":"s001","room":"304"},{"id":"l004","weekday":1,"period":2,"subjectId":"s003","room":"304"},{"id":"l006","weekday":1,"period":3,"subjectId":"s005","room":"306"},{"id":"l008","weekday":1,"period":4,"subjectId":"s007","room":"115"},{"id":"l00a","weekday":1,"period":5,"subjectId":"s009","room":"207"},{"id":"l00b","weekday":1,"period":6,"subjectId":"s009","room":"207"},{"id":"l00d","weekday":2,"period":1,"subjectId":"s00c","room":"221"},{"id":"l00e","weekday":2,"period":2,"subjectId":"s00c","room":"221"},{"id":"l00g","weekday":2,"period":3,"subjectId":"s00f","room":"208"},{"id":"l00i","weekday":2,"period":4,"subjectId":"s00h","room":""},{"id":"l00k","weekday":2,"period":5,"subjectId":"s00j","room":"114"},{"id":"l00l","weekday":2,"period":6,"subjectId":"s00j","room":"114"},{"id":"l00n","weekday":3,"period":1,"subjectId":"s00m","room":"304"},{"id":"l00o","weekday":3,"period":2,"subjectId":"s003","room":"304"},{"id":"l00p","weekday":3,"period":3,"subjectId":"s003","room":"304"},{"id":"l00r","weekday":3,"period":4,"subjectId":"s00q","room":"207"},{"id":"l00s","weekday":3,"period":5,"subjectId":"s00q","room":"207"},{"id":"l00t","weekday":3,"period":6,"subjectId":"s00h","room":""},{"id":"l00v","weekday":3,"period":7,"subjectId":"s00u","room":"115"},{"id":"l00w","weekday":3,"period":8,"subjectId":"s00j","room":"115"},{"id":"l00y","weekday":4,"period":1,"subjectId":"s00x","room":"309"},{"id":"l00z","weekday":4,"period":2,"subjectId":"s003","room":"304"},{"id":"l011","weekday":4,"period":3,"subjectId":"s010","room":"304"},{"id":"l012","weekday":4,"period":4,"subjectId":"s010","room":"304"},{"id":"l013","weekday":4,"period":5,"subjectId":"s00q","room":"207"},{"id":"l015","weekday":4,"period":6,"subjectId":"s014","room":"207"},{"id":"l017","weekday":4,"period":7,"subjectId":"s016","room":"310"},{"id":"l018","weekday":4,"period":8,"subjectId":"s016","room":"310"},{"id":"l01a","weekday":5,"period":1,"subjectId":"s019","room":"304"},{"id":"l01b","weekday":5,"period":2,"subjectId":"s019","room":"304"},{"id":"l01c","weekday":5,"period":3,"subjectId":"s010","room":"304"},{"id":"l01d","weekday":5,"period":4,"subjectId":"s010","room":"304"},{"id":"l01f","weekday":5,"period":5,"subjectId":"s01e","room":"108"},{"id":"l01g","weekday":5,"period":6,"subjectId":"s014","room":"207"},{"id":"l01i","weekday":5,"period":7,"subjectId":"s01h","room":"219"},{"id":"l01k","weekday":5,"period":8,"subjectId":"s01j","room":"307"},{"id":"l01m","weekday":6,"period":2,"subjectId":"s01l","room":"106/309"},{"id":"l01o","weekday":6,"period":3,"subjectId":"s01n","room":"115"},{"id":"l01p","weekday":6,"period":4,"subjectId":"s01n","room":"115"},{"id":"l01q","weekday":6,"period":5,"subjectId":"s01h","room":"219"},{"id":"l01r","weekday":6,"period":6,"subjectId":"s01h","room":"219"}],"bells":{"dayStart":"08:00","lessonLen":40,"breakLen":10}}$json$::jsonb)
on conflict (id) do nothing;
