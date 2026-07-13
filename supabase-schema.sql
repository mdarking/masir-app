-- =========================================================
-- مسیر — سیستم لایسنس / لینک اختصاصی
-- این فایل رو یک‌بار توی Supabase SQL Editor اجرا کن.
-- =========================================================

create extension if not exists pgcrypto;

create table if not exists licenses (
  id                uuid primary key default gen_random_uuid(),
  link_token        text unique not null,      -- می‌ره توی لینک: ?l=xxxx
  code_hash         text not null,             -- کد فعال‌سازی، هش‌شده (نه متن ساده)
  customer_name     text,                      -- فقط برای یادداشت خودت
  device_fingerprint text,                     -- بعد از اولین فعال‌سازی پر می‌شه
  status            text not null default 'pending', -- pending | active | revoked
  created_at        timestamptz not null default now(),
  activated_at      timestamptz
);

alter table licenses enable row level security;
-- عمداً هیچ policy ای برای select/insert/update مستقیم تعریف نمی‌کنیم.
-- تمام دسترسی‌ها فقط از طریق توابع زیر (security definer) انجام می‌شه.

-- ---------------------------------------------------------
-- تابع ۱: ساخت لایسنس جدید (فقط خودِ ادمین لاگین‌شده می‌تونه صداش بزنه)
-- ---------------------------------------------------------
create or replace function create_license(p_customer text default null)
returns jsonb
language plpgsql
security definer
set search_path = public
as $$
declare
  v_token text;
  v_code  text;
begin
  if auth.uid() is null then
    raise exception 'not authorized';
  end if;

  v_token := encode(gen_random_bytes(6), 'hex');           -- مثلا: 9f3a1b2c4d5e
  v_code  := lpad(floor(random() * 1000000)::text, 6, '0'); -- کد ۶ رقمی، مثلا 042871

  insert into licenses (link_token, code_hash, customer_name)
  values (v_token, crypt(v_code, gen_salt('bf')), p_customer);

  -- کد فقط همین یک‌بار به‌صورت متن ساده برمی‌گرده؛ جایی ذخیره نمی‌شه
  return jsonb_build_object('token', v_token, 'code', v_code);
end;
$$;
grant execute on function create_license(text) to authenticated;

-- ---------------------------------------------------------
-- تابع ۲: لیست لایسنس‌ها برای پنل ادمین (بدون نمایش کد)
-- ---------------------------------------------------------
create or replace function list_licenses()
returns table (
  id uuid, link_token text, customer_name text,
  status text, device_locked boolean,
  created_at timestamptz, activated_at timestamptz
)
language plpgsql
security definer
set search_path = public
as $$
begin
  if auth.uid() is null then
    raise exception 'not authorized';
  end if;

  return query
    select l.id, l.link_token, l.customer_name, l.status,
           (l.device_fingerprint is not null), l.created_at, l.activated_at
    from licenses l
    order by l.created_at desc;
end;
$$;
grant execute on function list_licenses() to authenticated;

-- ---------------------------------------------------------
-- تابع ۳: باطل‌کردن یک لایسنس برای همیشه
-- ---------------------------------------------------------
create or replace function revoke_license(p_id uuid)
returns void
language plpgsql
security definer
set search_path = public
as $$
begin
  if auth.uid() is null then
    raise exception 'not authorized';
  end if;
  update licenses set status = 'revoked' where id = p_id;
end;
$$;
grant execute on function revoke_license(uuid) to authenticated;

-- ---------------------------------------------------------
-- تابع ۴: ریست کردن قفلِ دستگاه (برای وقتی مشتری گوشیش عوض شده)
-- کد قبلی همچنان معتبر می‌مونه و می‌تونه یک‌بار دیگه روی دستگاه
-- جدید فعال بشه.
-- ---------------------------------------------------------
create or replace function reset_license(p_id uuid)
returns void
language plpgsql
security definer
set search_path = public
as $$
begin
  if auth.uid() is null then
    raise exception 'not authorized';
  end if;
  update licenses
  set status = 'pending', device_fingerprint = null, activated_at = null
  where id = p_id and status <> 'revoked';
end;
$$;
grant execute on function reset_license(uuid) to authenticated;

-- ---------------------------------------------------------
-- تابع ۵: فعال‌سازی — این تنها تابعیه که خودِ اپ (بدون لاگین) صدا می‌زنه
-- ---------------------------------------------------------
create or replace function activate_license(p_token text, p_code text, p_device text)
returns jsonb
language plpgsql
security definer
set search_path = public
as $$
declare
  rec licenses%rowtype;
begin
  select * into rec from licenses where link_token = p_token;

  if not found then
    return jsonb_build_object('ok', false, 'error', 'not_found');
  end if;

  if rec.status = 'revoked' then
    return jsonb_build_object('ok', false, 'error', 'revoked');
  end if;

  if rec.code_hash <> crypt(p_code, rec.code_hash) then
    return jsonb_build_object('ok', false, 'error', 'bad_code');
  end if;

  if rec.status = 'active' then
    if rec.device_fingerprint = p_device then
      return jsonb_build_object('ok', true, 'status', 'already-this-device');
    else
      return jsonb_build_object('ok', false, 'error', 'already_used');
    end if;
  end if;

  update licenses
  set status = 'active', device_fingerprint = p_device, activated_at = now()
  where id = rec.id;

  return jsonb_build_object('ok', true, 'status', 'activated');
end;
$$;
grant execute on function activate_license(text, text, text) to anon;
grant execute on function activate_license(text, text, text) to authenticated;
