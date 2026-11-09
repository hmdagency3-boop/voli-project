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

-- Called by the app server on every open; records the visit and answers whether it is banned.
create or replace function public.device_check_in(
  p_device_id text, p_ip text, p_country text, p_user_agent text, p_platform text,
  p_model text, p_brand text, p_os_version text, p_connection text
) returns table(banned boolean, kind text, until timestamptz, reason text)
language plpgsql security definer set search_path = '' as $$
declare v_ip inet;
begin
  begin v_ip := nullif(p_ip, '')::inet; exception when others then v_ip := null; end;
  insert into public.device_visits(auth_id, device_id, ip, country, user_agent, platform, model, brand, os_version, connection)
  values (auth.uid(), left(coalesce(p_device_id,'unknown'),100), v_ip, left(p_country,8), left(p_user_agent,500),
          left(p_platform,50), left(p_model,100), left(p_brand,100), left(p_os_version,50), left(p_connection,30));
  return query
    select true, b.kind, b.until, b.reason from public.device_bans b
    where (b.until is null or b.until > now())
      and ((b.kind = 'device' and b.device_id = p_device_id) or (b.kind <> 'device' and v_ip is not null and v_ip <<= b.net))
    order by b.until desc nulls first limit 1;
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
      and not exists (select 1 from public.device_bans b where b.kind='device' and b.device_id = v.device_id);
  get diagnostics n = row_count;
  insert into public.device_bans(kind, net, reason, until, created_by)
    select distinct 'ip', set_masklen(v.ip, case when family(v.ip)=4 then 32 else 128 end)::cidr, p_reason, p_until, me
    from public.device_visits v where v.auth_id = target and v.ip is not null
      and not exists (select 1 from public.device_bans b where b.kind='ip' and v.ip <<= b.net);
  if p_networks then
    insert into public.device_bans(kind, net, reason, until, created_by)
      select distinct 'network', network(set_masklen(v.ip, case when family(v.ip)=4 then 24 else 48 end))::cidr, p_reason, p_until, me
      from public.device_visits v where v.auth_id = target and v.ip is not null
        and not exists (select 1 from public.device_bans b where b.kind='network' and v.ip <<= b.net);
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
