-- voli: device & network logging + bans by IP, whole network, or phone.
-- Re-runnable. Run in the SQL Editor after 009_admin.sql.

-- Every app open: who (if signed in), IP, network, phone details.
create table if not exists public.device_visits (
  id bigserial primary key,
  auth_id uuid references auth.users(id) on delete set null,
  device_id text not null,
  ip inet,
  country text,
  user_agent text,
  platform text,
  model text,
  brand text,
  os_version text,
  connection text,
  created_at timestamptz not null default now()
);
create index if not exists device_visits_auth_idx on public.device_visits(auth_id, created_at desc);
create index if not exists device_visits_ip_idx on public.device_visits(ip);
create index if not exists device_visits_device_idx on public.device_visits(device_id);
revoke all on public.device_visits from anon, authenticated;
grant all on public.device_visits to service_role;
grant usage, select on sequence public.device_visits_id_seq to service_role;
alter table public.device_visits enable row level security;

-- kind: 'ip' (one address), 'network' (whole range, e.g. 41.33.12.0/24), 'device' (one phone).
create table if not exists public.device_bans (
  id bigserial primary key,
  kind text not null check (kind in ('ip','network','device')),
  net cidr,
  device_id text,
  reason text,
  until timestamptz,
  created_by uuid,
  created_at timestamptz not null default now(),
  check ((kind = 'device') = (device_id is not null)),
  check ((kind <> 'device') = (net is not null))
);
revoke all on public.device_bans from anon, authenticated;
grant all on public.device_bans to service_role;
alter table public.device_bans enable row level security;

-- One stable, shared notice code for each ban, including existing member bans.
create sequence if not exists public.ban_notice_code_seq start with 200;
revoke all on sequence public.ban_notice_code_seq from public, anon, authenticated;
grant usage, select on sequence public.ban_notice_code_seq to service_role;
alter table public.device_bans add column if not exists ban_code bigint;
alter table public.member_bans add column if not exists ban_code bigint;
select setval('public.ban_notice_code_seq', greatest(200,
  (select last_value from public.ban_notice_code_seq),
  coalesce((select max(ban_code) + 1 from public.device_bans), 200),
  coalesce((select max(ban_code) + 1 from public.member_bans), 200)), false);
update public.device_bans set ban_code = nextval('public.ban_notice_code_seq') where ban_code is null;
update public.member_bans set ban_code = nextval('public.ban_notice_code_seq') where ban_code is null;
alter table public.device_bans alter column ban_code set default nextval('public.ban_notice_code_seq');
alter table public.member_bans alter column ban_code set default nextval('public.ban_notice_code_seq');
alter table public.device_bans alter column ban_code set not null;
alter table public.member_bans alter column ban_code set not null;
create unique index if not exists device_bans_code_idx on public.device_bans(ban_code);
create unique index if not exists member_bans_code_idx on public.member_bans(ban_code);

-- Historical signed-in visits are the account/device links. Never expose these
-- links to members. Do not copy bans: lifting/expiry must release linked accounts.
create or replace function public.account_device_ban(p_auth uuid)
returns table(until timestamptz, reason text, ban_code bigint)
language sql stable security definer set search_path = '' as $$
  select b.until, b.reason, b.ban_code from public.device_bans b
  where b.kind = 'device' and (b.until is null or b.until > now())
    and exists (select 1 from public.device_visits v
      where v.auth_id = p_auth and v.device_id = b.device_id and v.device_id <> 'unknown')
  order by b.until desc nulls first, b.ban_code limit 1
$$;
revoke all on function public.account_device_ban(uuid) from public, anon, authenticated;

-- Existing server-side member permission checks also recognize linked bans.
create or replace function public.is_banned(p_auth uuid) returns boolean
language sql stable security definer set search_path = '' as $$
  select exists (select 1 from public.member_bans b where b.auth_id = p_auth and (b.until is null or b.until > now()))
    or exists (select 1 from public.account_device_ban(p_auth))
$$;
revoke all on function public.is_banned(uuid) from public, anon, authenticated;

drop function if exists public.my_ban();
create function public.my_ban() returns table(until timestamptz, reason text, ban_code bigint)
language sql stable security definer set search_path = '' as $$
  select b.until, b.reason, b.ban_code from (
    select m.until, m.reason, m.ban_code from public.member_bans m
      where m.auth_id = auth.uid() and (m.until is null or m.until > now())
    union all select d.until, d.reason, d.ban_code from public.account_device_ban(auth.uid()) d
  ) b order by b.until desc nulls first, b.ban_code limit 1
$$;
revoke all on function public.my_ban() from public, anon;
grant execute on function public.my_ban() to authenticated;

-- Called by the app server on every open; records the visit and answers whether it is banned.
drop function if exists public.device_check_in(text,text,text,text,text,text,text,text,text);
create function public.device_check_in(
  p_device_id text, p_ip text, p_country text, p_user_agent text, p_platform text,
  p_model text, p_brand text, p_os_version text, p_connection text
) returns table(banned boolean, kind text, until timestamptz, reason text, ban_code bigint)
language plpgsql security definer set search_path = '' as $$
declare v_ip inet;
begin
  begin v_ip := nullif(p_ip, '')::inet; exception when others then v_ip := null; end;
  insert into public.device_visits(auth_id, device_id, ip, country, user_agent, platform, model, brand, os_version, connection)
  values (auth.uid(), left(coalesce(p_device_id,'unknown'),100), v_ip, left(p_country,8), left(p_user_agent,500),
          left(p_platform,50), left(p_model,100), left(p_brand,100), left(p_os_version,50), left(p_connection,30));
  return query
    select true, case when b.kind = 'device' and b.device_id <> p_device_id then 'account' else b.kind end,
      b.until, b.reason, b.ban_code from public.device_bans b
    where (b.until is null or b.until > now())
      and ((b.kind = 'device' and (b.device_id = p_device_id or exists (
        select 1 from public.device_visits v where v.auth_id = auth.uid() and v.device_id = b.device_id
          and v.device_id <> 'unknown'
      ))) or (b.kind <> 'device' and v_ip is not null and v_ip <<= b.net))
    order by b.until desc nulls first, b.ban_code limit 1;
end $$;
revoke all on function public.device_check_in(text,text,text,text,text,text,text,text,text) from public;
grant execute on function public.device_check_in(text,text,text,text,text,text,text,text,text) to anon, authenticated;

-- ---------- Management (SQL Editor / admins only) ----------
-- Ban everything a member has used: their phones, their IPs (and optionally whole networks).
-- Example: select public.ban_member_devices(1234567, true, 'spam', null);
create or replace function public.ban_member_devices(p_public_id bigint, p_networks boolean default false,
  p_reason text default null, p_until timestamptz default null) returns integer
language plpgsql security definer set search_path = '' as $$
declare me uuid := auth.uid(); target uuid; n integer := 0;
begin
  if me is not null then perform public.admin_guard(); end if;
  select p.auth_id into target from public.profiles p where p.public_id = p_public_id;
  if target is null then raise exception 'Member not found'; end if;
  insert into public.device_bans(kind, device_id, reason, until, created_by)
    select distinct 'device', v.device_id, p_reason, p_until, me from public.device_visits v
    where v.auth_id = target and v.device_id <> 'unknown'
      and not exists (select 1 from public.device_bans b where b.kind='device' and b.device_id = v.device_id
        and (b.until is null or b.until > now()));
  get diagnostics n = row_count;
  insert into public.device_bans(kind, net, reason, until, created_by)
    select distinct 'ip', set_masklen(v.ip, case when family(v.ip)=4 then 32 else 128 end)::cidr, p_reason, p_until, me
    from public.device_visits v where v.auth_id = target and v.ip is not null
      and not exists (select 1 from public.device_bans b where b.kind='ip' and v.ip <<= b.net
        and (b.until is null or b.until > now()));
  if p_networks then
    insert into public.device_bans(kind, net, reason, until, created_by)
      select distinct 'network', network(set_masklen(v.ip, case when family(v.ip)=4 then 24 else 48 end))::cidr, p_reason, p_until, me
      from public.device_visits v where v.auth_id = target and v.ip is not null
        and not exists (select 1 from public.device_bans b where b.kind='network' and v.ip <<= b.net
          and (b.until is null or b.until > now()));
  end if;
  return n;
end $$;
revoke all on function public.ban_member_devices(bigint,boolean,text,timestamptz) from public, anon;
grant execute on function public.ban_member_devices(bigint,boolean,text,timestamptz) to authenticated;

-- Direct bans: select public.ban_ip('41.33.12.7'); select public.ban_network('41.33.12.0/24');
create or replace function public.ban_ip(p_ip text, p_reason text default null, p_until timestamptz default null) returns void
language plpgsql security definer set search_path = '' as $$
begin
  if auth.uid() is not null then perform public.admin_guard(); end if;
  insert into public.device_bans(kind, net, reason, until, created_by) values ('ip', p_ip::inet::cidr, p_reason, p_until, auth.uid());
end $$;
create or replace function public.ban_network(p_net text, p_reason text default null, p_until timestamptz default null) returns void
language plpgsql security definer set search_path = '' as $$
begin
  if auth.uid() is not null then perform public.admin_guard(); end if;
  insert into public.device_bans(kind, net, reason, until, created_by) values ('network', network(p_net::inet)::cidr, p_reason, p_until, auth.uid());
end $$;
revoke all on function public.ban_ip(text,text,timestamptz) from public, anon;
revoke all on function public.ban_network(text,text,timestamptz) from public, anon;
grant execute on function public.ban_ip(text,text,timestamptz) to authenticated;
grant execute on function public.ban_network(text,text,timestamptz) to authenticated;

-- Look up a member's devices:  select * from public.device_visits v join public.profiles p on p.auth_id=v.auth_id where p.public_id=1234567 order by v.created_at desc;
-- Lift a ban:                  delete from public.device_bans where id = ...;
-- Or lift by displayed code:   delete from public.device_bans where ban_code = 200;
-- All accounts that used a banned device inherit its code/reason on any device.
