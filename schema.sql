-- Travel Checklist DB schema (travel.dev-quik.com)
-- Mirrors the NFL pick'em login pattern: users table + bcrypt (pgcrypto)
-- + uuid session tokens, all access through SECURITY DEFINER RPCs.
-- The anon PostgREST role gets EXECUTE on the RPCs only; no table grants.

create extension if not exists pgcrypto;

-- ---------- tables ----------

create table if not exists users (
  id            uuid        primary key default gen_random_uuid(),
  username      text        not null,
  password_hash text        not null,
  nickname      text,
  email         text,
  created_at    timestamptz not null default now()
);
create unique index if not exists users_username_uniq on users (lower(username));
create unique index if not exists users_email_uniq on users (lower(email));

create table if not exists sessions (
  token      uuid        primary key default gen_random_uuid(),
  user_id    uuid        not null references users(id) on delete cascade,
  created_at timestamptz not null default now()
);
create index if not exists sessions_user_idx on sessions (user_id);

create table if not exists trips (
  id          uuid        primary key default gen_random_uuid(),
  user_id     uuid        not null references users(id) on delete cascade,
  name        text        not null,
  destination text,
  start_date  date,
  end_date    date,
  notes       text,
  created_at  timestamptz not null default now()
);
create index if not exists trips_user_idx on trips (user_id, created_at desc);

create table if not exists checklist_items (
  id         uuid        primary key default gen_random_uuid(),
  trip_id    uuid        not null references trips(id) on delete cascade,
  label      text        not null,
  category   text        not null default 'Misc',
  is_checked boolean     not null default false,
  sort_order int         not null default 0,
  created_at timestamptz not null default now()
);
create index if not exists checklist_items_trip_idx on checklist_items (trip_id, sort_order, created_at);

-- ---------- helpers ----------

create or replace function _travel_uid(p_token uuid)
returns uuid
language plpgsql
security definer
set search_path to 'public'
as $$
declare v_uid uuid;
begin
  select s.user_id into v_uid from sessions s where s.token = p_token limit 1;
  if v_uid is null then
    raise exception 'invalid_session:Please sign in again.';
  end if;
  return v_uid;
end $$;

create or replace function _travel_trip(p_uid uuid, p_trip_id uuid)
returns trips
language plpgsql
security definer
set search_path to 'public'
as $$
declare v_t trips%rowtype;
begin
  select * into v_t from trips t where t.id = p_trip_id and t.user_id = p_uid limit 1;
  if v_t.id is null then
    raise exception 'Trip not found.';
  end if;
  return v_t;
end $$;

create or replace function _travel_item(p_uid uuid, p_item_id uuid)
returns checklist_items
language plpgsql
security definer
set search_path to 'public'
as $$
declare v_i checklist_items%rowtype;
begin
  select i.* into v_i
  from checklist_items i
  join trips t on t.id = i.trip_id
  where i.id = p_item_id and t.user_id = p_uid
  limit 1;
  if v_i.id is null then
    raise exception 'Item not found.';
  end if;
  return v_i;
end $$;

create or replace function _travel_clean_email(p_email text, p_required boolean)
returns text
language plpgsql
security definer
set search_path to 'public'
as $$
declare v text := lower(trim(coalesce(p_email, '')));
begin
  if v = '' then
    if p_required then raise exception 'Enter an email address.'; end if;
    return null;
  end if;
  if v !~ '^[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}$' then
    raise exception 'That email address does not look valid.';
  end if;
  return v;
end $$;

-- ---------- auth (mirrors football user_login / pool_register) ----------

create or replace function travel_register(p_username text, p_password text,
  p_email text default null, p_nickname text default null)
returns json
language plpgsql
security definer
set search_path to 'public'
as $$
declare
  v_uname text := trim(coalesce(p_username, ''));
  v_pw    text := coalesce(p_password, '');
  v_nick  text := nullif(trim(coalesce(p_nickname, '')), '');
  v_email text;
  v_uid   uuid;
  v_token uuid;
begin
  if v_uname = '' then raise exception 'Pick a username.'; end if;
  if char_length(v_uname) > 40 then raise exception 'Username must be 40 characters or less.'; end if;
  if char_length(v_pw) < 8 then raise exception 'Password must be at least 8 characters.'; end if;
  v_email := _travel_clean_email(p_email, false);
  if exists (select 1 from users where lower(username) = lower(v_uname)) then
    raise exception 'That username is taken — try signing in instead.';
  end if;
  if v_email is not null and exists (select 1 from users where lower(email) = v_email) then
    raise exception 'That email is already registered — try signing in instead.';
  end if;
  insert into users (username, password_hash, nickname, email)
  values (v_uname, crypt(v_pw, gen_salt('bf')), v_nick, v_email)
  returning id into v_uid;
  insert into sessions (user_id) values (v_uid) returning token into v_token;
  return json_build_object('token', v_token, 'user_id', v_uid,
    'username', v_uname, 'nickname', v_nick, 'email', v_email);
end $$;

create or replace function travel_login(p_username text, p_password text)
returns json
language plpgsql
security definer
set search_path to 'public'
as $$
declare
  v_uname text := trim(coalesce(p_username, ''));
  v_pw    text := coalesce(p_password, '');
  v_u     users%rowtype;
  v_token uuid;
begin
  if v_uname = '' then raise exception 'Enter your username.'; end if;
  select * into v_u from users where lower(username) = lower(v_uname) limit 1;
  if v_u.id is null or crypt(v_pw, v_u.password_hash) <> v_u.password_hash then
    raise exception 'Wrong username or password.';
  end if;
  insert into sessions (user_id) values (v_u.id) returning token into v_token;
  return json_build_object('token', v_token, 'user_id', v_u.id,
    'username', v_u.username, 'nickname', v_u.nickname, 'email', v_u.email);
end $$;

create or replace function travel_me(p_token uuid)
returns json
language plpgsql
security definer
set search_path to 'public'
as $$
declare v_uid uuid; v_u users%rowtype;
begin
  v_uid := _travel_uid(p_token);
  select * into v_u from users where id = v_uid;
  return json_build_object('token', p_token, 'user_id', v_u.id,
    'username', v_u.username, 'nickname', v_u.nickname, 'email', v_u.email);
end $$;

create or replace function travel_logout(p_token uuid)
returns boolean
language plpgsql
security definer
set search_path to 'public'
as $$
begin
  delete from sessions where token = p_token;
  return true;
end $$;

-- ---------- trips ----------

create or replace function travel_trips(p_token uuid)
returns json
language plpgsql
security definer
set search_path to 'public'
as $$
declare v_uid uuid;
begin
  v_uid := _travel_uid(p_token);
  return coalesce((
    select json_agg(t order by coalesce(t.start_date, '9999-12-31'), t.created_at desc)
    from (
      select tr.id, tr.name, tr.destination, tr.start_date, tr.end_date, tr.notes, tr.created_at,
        (select count(*) from checklist_items i where i.trip_id = tr.id) as total_items,
        (select count(*) from checklist_items i where i.trip_id = tr.id and i.is_checked) as checked_items
      from trips tr
      where tr.user_id = v_uid
    ) t
  ), '[]'::json);
end $$;

create or replace function travel_trip_create(p_token uuid, p_name text,
  p_destination text default null, p_start_date date default null,
  p_end_date date default null, p_notes text default null)
returns json
language plpgsql
security definer
set search_path to 'public'
as $$
declare
  v_uid  uuid;
  v_name text := trim(coalesce(p_name, ''));
  v_tr   trips%rowtype;
begin
  v_uid := _travel_uid(p_token);
  if v_name = '' then raise exception 'Give the trip a name.'; end if;
  if char_length(v_name) > 80 then raise exception 'Trip name must be 80 characters or less.'; end if;
  if p_start_date is not null and p_end_date is not null and p_end_date < p_start_date then
    raise exception 'The end date is before the start date.';
  end if;
  insert into trips (user_id, name, destination, start_date, end_date, notes)
  values (v_uid, v_name, nullif(trim(coalesce(p_destination, '')), ''),
          p_start_date, p_end_date, nullif(trim(coalesce(p_notes, '')), ''))
  returning * into v_tr;
  return json_build_object('id', v_tr.id, 'name', v_tr.name, 'destination', v_tr.destination,
    'start_date', v_tr.start_date, 'end_date', v_tr.end_date, 'notes', v_tr.notes,
    'created_at', v_tr.created_at, 'total_items', 0, 'checked_items', 0);
end $$;

create or replace function travel_trip_update(p_token uuid, p_trip_id uuid, p_name text,
  p_destination text default null, p_start_date date default null,
  p_end_date date default null, p_notes text default null)
returns json
language plpgsql
security definer
set search_path to 'public'
as $$
declare
  v_uid  uuid;
  v_name text := trim(coalesce(p_name, ''));
begin
  v_uid := _travel_uid(p_token);
  perform _travel_trip(v_uid, p_trip_id);
  if v_name = '' then raise exception 'Give the trip a name.'; end if;
  if char_length(v_name) > 80 then raise exception 'Trip name must be 80 characters or less.'; end if;
  if p_start_date is not null and p_end_date is not null and p_end_date < p_start_date then
    raise exception 'The end date is before the start date.';
  end if;
  update trips
  set name = v_name,
      destination = nullif(trim(coalesce(p_destination, '')), ''),
      start_date = p_start_date, end_date = p_end_date,
      notes = nullif(trim(coalesce(p_notes, '')), '')
  where id = p_trip_id;
  return json_build_object('id', p_trip_id, 'ok', true);
end $$;

create or replace function travel_trip_delete(p_token uuid, p_trip_id uuid)
returns boolean
language plpgsql
security definer
set search_path to 'public'
as $$
declare v_uid uuid;
begin
  v_uid := _travel_uid(p_token);
  perform _travel_trip(v_uid, p_trip_id);
  delete from trips where id = p_trip_id;
  return true;
end $$;

-- ---------- checklist items ----------

create or replace function travel_items(p_token uuid, p_trip_id uuid)
returns json
language plpgsql
security definer
set search_path to 'public'
as $$
declare v_uid uuid;
begin
  v_uid := _travel_uid(p_token);
  perform _travel_trip(v_uid, p_trip_id);
  return coalesce((
    select json_agg(i order by i.sort_order, i.created_at)
    from (
      select id, label, category, is_checked, sort_order, created_at
      from checklist_items where trip_id = p_trip_id
    ) i
  ), '[]'::json);
end $$;

create or replace function travel_item_add(p_token uuid, p_trip_id uuid, p_label text,
  p_category text default 'Misc')
returns json
language plpgsql
security definer
set search_path to 'public'
as $$
declare
  v_uid  uuid;
  v_label text := trim(coalesce(p_label, ''));
  v_cat   text := nullif(trim(coalesce(p_category, '')), '');
  v_i     checklist_items%rowtype;
  v_next  int;
begin
  v_uid := _travel_uid(p_token);
  perform _travel_trip(v_uid, p_trip_id);
  if v_label = '' then raise exception 'Write what to pack first.'; end if;
  if char_length(v_label) > 120 then raise exception 'Item text must be 120 characters or less.'; end if;
  if v_cat is null then v_cat := 'Misc'; end if;
  if char_length(v_cat) > 30 then raise exception 'Category must be 30 characters or less.'; end if;
  select coalesce(max(sort_order), -1) + 1 into v_next from checklist_items where trip_id = p_trip_id;
  insert into checklist_items (trip_id, label, category, sort_order)
  values (p_trip_id, v_label, v_cat, v_next)
  returning * into v_i;
  return json_build_object('id', v_i.id, 'label', v_i.label, 'category', v_i.category,
    'is_checked', v_i.is_checked, 'sort_order', v_i.sort_order, 'created_at', v_i.created_at);
end $$;

create or replace function travel_item_toggle(p_token uuid, p_item_id uuid)
returns json
language plpgsql
security definer
set search_path to 'public'
as $$
declare
  v_uid uuid;
  v_i   checklist_items%rowtype;
begin
  v_uid := _travel_uid(p_token);
  v_i := _travel_item(v_uid, p_item_id);
  update checklist_items set is_checked = not v_i.is_checked where id = p_item_id
  returning * into v_i;
  return json_build_object('id', v_i.id, 'is_checked', v_i.is_checked);
end $$;

create or replace function travel_item_update(p_token uuid, p_item_id uuid, p_label text,
  p_category text default null)
returns json
language plpgsql
security definer
set search_path to 'public'
as $$
declare
  v_uid   uuid;
  v_i     checklist_items%rowtype;
  v_label text := trim(coalesce(p_label, ''));
  v_cat   text := nullif(trim(coalesce(p_category, '')), '');
begin
  v_uid := _travel_uid(p_token);
  v_i := _travel_item(v_uid, p_item_id);
  if v_label = '' then raise exception 'Write what to pack first.'; end if;
  if char_length(v_label) > 120 then raise exception 'Item text must be 120 characters or less.'; end if;
  if v_cat is not null and char_length(v_cat) > 30 then raise exception 'Category must be 30 characters or less.'; end if;
  update checklist_items
  set label = v_label, category = coalesce(v_cat, category)
  where id = p_item_id
  returning * into v_i;
  return json_build_object('id', v_i.id, 'label', v_i.label, 'category', v_i.category,
    'is_checked', v_i.is_checked);
end $$;

create or replace function travel_item_delete(p_token uuid, p_item_id uuid)
returns boolean
language plpgsql
security definer
set search_path to 'public'
as $$
declare v_uid uuid;
begin
  v_uid := _travel_uid(p_token);
  perform _travel_item(v_uid, p_item_id);
  delete from checklist_items where id = p_item_id;
  return true;
end $$;

create or replace function travel_seed_starter(p_token uuid, p_trip_id uuid)
returns json
language plpgsql
security definer
set search_path to 'public'
as $$
declare
  v_uid uuid;
  v_n   int := 0;
  r record;
begin
  v_uid := _travel_uid(p_token);
  perform _travel_trip(v_uid, p_trip_id);
  for r in
    select * from (values
      ('Documents','Passport / ID'),
      ('Documents','Boarding passes'),
      ('Documents','Hotel confirmation'),
      ('Documents','Travel insurance info'),
      ('Documents','Tickets / wristbands'),
      ('Clothing','Tops'),
      ('Clothing','Bottoms'),
      ('Clothing','Underwear & socks'),
      ('Clothing','Sleepwear'),
      ('Clothing','Jacket / layers'),
      ('Clothing','Comfortable walking shoes'),
      ('Toiletries','Toiletry kit'),
      ('Toiletries','Toothbrush & toothpaste'),
      ('Toiletries','Deodorant'),
      ('Toiletries','Shampoo & conditioner'),
      ('Toiletries','Medications'),
      ('Toiletries','Lysol'),
      ('Electronics','Phone charger'),
      ('Electronics','Battery banks'),
      ('Electronics','iPad'),
      ('Electronics','Laptop'),
      ('Electronics','Bluetooth speakers'),
      ('Electronics','Cable case'),
      ('Electronics','Extension cord'),
      ('Electronics','Apple TV + remote'),
      ('Electronics','Headphones'),
      ('Electronics','Travel adapter'),
      ('Food & Drink','Cooler'),
      ('Food & Drink','Alcohol'),
      ('Food & Drink','Snacks & water bottle'),
      ('Comfort','Pillows'),
      ('Comfort','Trash bags'),
      ('Personal','Vape'),
      ('Health','Sunscreen'),
      ('Health','First-aid basics'),
      ('Health','Any prescriptions')
    ) as s(cat, lbl)
  loop
    insert into checklist_items (trip_id, label, category, sort_order)
    values (p_trip_id, r.lbl, r.cat, v_n);
    v_n := v_n + 1;
  end loop;
  return json_build_object('added', v_n);
end $$;

-- ---------- lockdown: anon may only EXECUTE the RPCs ----------

revoke all on schema public from anon;
grant usage on schema public to anon;
revoke all on all functions in schema public from public;
grant execute on all functions in schema public to anon;
alter default privileges in schema public revoke all on functions from public;
alter default privileges in schema public grant execute on functions to anon;
