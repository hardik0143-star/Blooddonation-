-- DonorLink Global — Mobile Upload Edition / fresh Supabase schema
-- Run once in a NEW Supabase project using SQL Editor.
-- Security-sensitive state is protected in PostgreSQL, not trusted to the browser.

create extension if not exists pgcrypto;

create table if not exists public.profiles (
  id uuid primary key references auth.users(id) on delete cascade,
  full_name text not null,
  role text not null check (role in ('donor','requester','hospital','blood_bank','ngo','admin')),
  country text not null,
  city text not null,
  blood_group text check (blood_group in ('A+','A-','B+','B-','AB+','AB-','O+','O-')),
  availability text not null default 'available' check (availability in ('available','urgent_only','unavailable')),
  availability_confirmed_at timestamptz default now(),
  phone text,
  latitude double precision check (latitude is null or latitude between -90 and 90),
  longitude double precision check (longitude is null or longitude between -180 and 180),
  matching_radius_km integer not null default 25 check (matching_radius_km between 1 and 200),
  preferred_language text not null default 'en' check(preferred_language in ('en','hi','gu')),
  is_identity_verified boolean not null default false,
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now()
);

create table if not exists public.organizations (
  id uuid primary key default gen_random_uuid(),
  owner_id uuid not null references public.profiles(id) on delete cascade,
  name text not null,
  type text not null check(type in ('hospital','blood_bank','ngo','red_cross_red_crescent','other')),
  country text not null,
  city text not null,
  license_reference text,
  website text,
  contact_phone text,
  verification_status text not null default 'pending' check(verification_status in ('pending','verified','rejected','suspended')),
  verification_note text,
  verified_at timestamptz,
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now()
);

create table if not exists public.blood_requests (
  id uuid primary key default gen_random_uuid(),
  created_by uuid not null references public.profiles(id) on delete cascade,
  organization_id uuid references public.organizations(id) on delete set null,
  blood_group text not null check (blood_group in ('A+','A-','B+','B-','AB+','AB-','O+','O-')),
  component text not null default 'RBC' check (component in ('RBC','Platelets','Plasma','Whole blood')),
  units integer not null default 1 check(units between 1 and 20),
  urgency text not null default 'urgent' check(urgency in ('critical','urgent','standard')),
  hospital_name text not null,
  country text not null,
  city text not null,
  latitude double precision check (latitude is null or latitude between -90 and 90),
  longitude double precision check (longitude is null or longitude between -180 and 180),
  needed_by timestamptz not null,
  notes text,
  status text not null default 'open' check(status in ('open','matched','fulfilled','cancelled','expired')),
  is_verified boolean not null default false,
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now()
);

create table if not exists public.donor_responses (
  id uuid primary key default gen_random_uuid(),
  request_id uuid not null references public.blood_requests(id) on delete cascade,
  donor_id uuid not null references public.profiles(id) on delete cascade,
  status text not null default 'offered' check(status in ('offered','accepted','declined','completed','cancelled')),
  message text,
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now(),
  unique(request_id, donor_id)
);

create table if not exists public.messages (
  id uuid primary key default gen_random_uuid(),
  response_id uuid not null references public.donor_responses(id) on delete cascade,
  sender_id uuid not null references public.profiles(id) on delete cascade,
  body text not null check (char_length(body) between 1 and 1500),
  created_at timestamptz not null default now()
);

create table if not exists public.notifications (
  id uuid primary key default gen_random_uuid(),
  user_id uuid not null references public.profiles(id) on delete cascade,
  title text not null,
  body text not null,
  href text,
  is_read boolean not null default false,
  created_at timestamptz not null default now()
);


create table if not exists public.abuse_reports (
  id uuid primary key default gen_random_uuid(),
  reporter_id uuid not null references public.profiles(id) on delete cascade,
  request_id uuid references public.blood_requests(id) on delete cascade,
  reason text not null check(char_length(reason) between 3 and 500),
  status text not null default 'open' check(status in ('open','reviewed','closed')),
  created_at timestamptz not null default now()
);

create table if not exists public.donation_confirmations (
  id uuid primary key default gen_random_uuid(),
  response_id uuid not null unique references public.donor_responses(id) on delete cascade,
  organization_id uuid not null references public.organizations(id) on delete cascade,
  confirmation_code text not null unique default upper(substr(replace(gen_random_uuid()::text,'-',''),1,10)),
  status text not null default 'confirmed' check(status in ('pending','confirmed','rejected')),
  confirmed_by uuid references public.profiles(id) on delete set null,
  confirmed_at timestamptz,
  created_at timestamptz not null default now()
);

-- Freshness timestamps are database-controlled.
create or replace function public.profile_guard() returns trigger
language plpgsql set search_path=public as $$
begin
  new.updated_at := now();
  if tg_op='INSERT' then
    if new.role='donor' then new.availability_confirmed_at := now(); end if;
  elsif new.role='donor' and new.availability is distinct from old.availability then
    new.availability_confirmed_at := now();
  end if;
  if tg_op='UPDATE' then
    new.id := old.id;
    new.role := old.role;
    new.is_identity_verified := old.is_identity_verified;
  end if;
  return new;
end $$;
drop trigger if exists profile_guard_trigger on public.profiles;
create trigger profile_guard_trigger before insert or update on public.profiles for each row execute procedure public.profile_guard();

-- Limit organization-registration spam.
create or replace function public.limit_owned_organizations() returns trigger
language plpgsql security definer set search_path=public as $$
begin
  if (select count(*) from public.organizations where owner_id=new.owner_id) >= 5 then
    raise exception 'Maximum organization limit reached';
  end if;
  new.verification_status := 'pending';
  new.verification_note := null;
  new.verified_at := null;
  return new;
end $$;
drop trigger if exists limit_owned_organizations_trigger on public.organizations;
create trigger limit_owned_organizations_trigger before insert on public.organizations for each row execute procedure public.limit_owned_organizations();

-- Requests can only inherit verification from a verified organization owned by the creator.
create or replace function public.request_guard() returns trigger
language plpgsql security definer set search_path=public as $$
declare ok boolean;
begin
  if tg_op='INSERT' then
    if (select count(*) from public.blood_requests where created_by=new.created_by and status in ('open','matched')) >= 10 then
      raise exception 'Maximum active request limit reached';
    end if;
  else
    new.created_by := old.created_by;
    new.is_verified := old.is_verified;
    new.organization_id := old.organization_id;
    new.blood_group := old.blood_group;
    new.component := old.component;
    new.units := old.units;
    new.urgency := old.urgency;
    new.hospital_name := old.hospital_name;
    new.country := old.country;
    new.city := old.city;
    new.latitude := old.latitude;
    new.longitude := old.longitude;
    new.needed_by := old.needed_by;
    new.notes := old.notes;
  end if;

  if new.organization_id is null then
    new.is_verified := false;
  else
    ok := exists(select 1 from public.organizations o where o.id=new.organization_id and o.owner_id=new.created_by and o.verification_status='verified');
    if not ok then raise exception 'Organization must be verified and owned by the request creator'; end if;
    new.is_verified := true;
  end if;
  new.updated_at := now();
  return new;
end $$;
drop trigger if exists request_guard_trigger on public.blood_requests;
create trigger request_guard_trigger before insert or update on public.blood_requests for each row execute procedure public.request_guard();

-- Public signup can NEVER create admin.
create or replace function public.handle_new_user() returns trigger
language plpgsql security definer set search_path=public as $$
declare safe_role text;
begin
  safe_role := case when new.raw_user_meta_data->>'role' in ('donor','requester','hospital','blood_bank','ngo')
    then new.raw_user_meta_data->>'role' else 'donor' end;
  insert into public.profiles(id,full_name,role,country,city,blood_group,preferred_language)
  values(
    new.id,
    left(coalesce(nullif(new.raw_user_meta_data->>'full_name',''),'Member'),120),
    safe_role,
    left(coalesce(nullif(new.raw_user_meta_data->>'country',''),'Unknown'),120),
    left(coalesce(nullif(new.raw_user_meta_data->>'city',''),'Unknown'),120),
    case when safe_role='donor' and new.raw_user_meta_data->>'blood_group' in ('A+','A-','B+','B-','AB+','AB-','O+','O-') then new.raw_user_meta_data->>'blood_group' else null end,
    case when new.raw_user_meta_data->>'preferred_language' in ('en','hi','gu') then new.raw_user_meta_data->>'preferred_language' else 'en' end
  );
  return new;
end $$;
drop trigger if exists on_auth_user_created on auth.users;
create trigger on_auth_user_created after insert on auth.users for each row execute procedure public.handle_new_user();

-- Validate donor offers and prevent direct API state forgery.
create or replace function public.response_guard() returns trigger
language plpgsql security definer set search_path=public as $$
declare
  request_owner uuid; donor_role text; donor_group text; donor_av text;
  req_group text; req_urg text; req_status text; req_needed timestamptz;
begin
  if tg_op='INSERT' then
    select created_by,blood_group,urgency,status,needed_by into request_owner,req_group,req_urg,req_status,req_needed
    from public.blood_requests where id=new.request_id;
    select role,blood_group,availability into donor_role,donor_group,donor_av from public.profiles where id=new.donor_id;
    if donor_role <> 'donor' then raise exception 'Only donor accounts can respond'; end if;
    if donor_av='unavailable' then raise exception 'Donor is unavailable'; end if;
    if donor_av='urgent_only' and req_urg='standard' then raise exception 'Donor accepts urgent requests only'; end if;
    if donor_group is distinct from req_group then raise exception 'Blood group does not match request'; end if;
    if req_status not in ('open','matched') or req_needed <= now() then raise exception 'Request is not accepting responses'; end if;
    new.status := 'offered';
    return new;
  end if;

  select created_by,blood_group,urgency,status,needed_by into request_owner,req_group,req_urg,req_status,req_needed
  from public.blood_requests where id=old.request_id;
  new.request_id:=old.request_id; new.donor_id:=old.donor_id; new.updated_at:=now();
  if new.status <> old.status then
    if auth.uid()=old.donor_id then
      if new.status='cancelled' and old.status in ('offered','accepted') then return new; end if;
      if new.status='offered' and old.status in ('cancelled','declined') then
        select blood_group,availability into donor_group,donor_av from public.profiles where id=old.donor_id;
        if donor_group is distinct from req_group or donor_av='unavailable' or (donor_av='urgent_only' and req_urg='standard') or req_status not in ('open','matched') or req_needed<=now() then
          raise exception 'Donor cannot reopen this response';
        end if;
        return new;
      end if;
      raise exception 'Donor cannot set this response status';
    elsif auth.uid()=request_owner then
      if new.status='accepted' and old.status='offered' then return new; end if;
      if new.status='declined' and old.status='offered' then return new; end if;
      if new.status='completed' and old.status='accepted' then return new; end if;
      if new.status='cancelled' and old.status in ('offered','accepted') then return new; end if;
      raise exception 'Invalid requester response transition';
    else
      raise exception 'Not authorized to update this response';
    end if;
  end if;
  return new;
end $$;
drop trigger if exists response_guard_trigger on public.donor_responses;
create trigger response_guard_trigger before insert or update on public.donor_responses for each row execute procedure public.response_guard();

-- Automatic donor notifications on new requests. Donor identities are never returned to requester.
create or replace function public.notify_matching_donors() returns trigger
language plpgsql security definer set search_path=public as $$
begin
  insert into public.notifications(user_id,title,body,href)
  select p.id,
    case when new.urgency='critical' then 'Critical blood request' else 'New blood request near you' end,
    new.blood_group || ' • ' || new.component || ' • ' || new.hospital_name || ', ' || new.city,
    '#requests'
  from public.profiles p
  where p.role='donor'
    and p.id<>new.created_by
    and p.blood_group=new.blood_group
    and p.availability<>'unavailable'
    and p.availability_confirmed_at >= now()-interval '60 days'
    and (p.availability='available' or new.urgency in ('critical','urgent'))
    and (
      (p.latitude is not null and p.longitude is not null and new.latitude is not null and new.longitude is not null
       and (6371*2*asin(sqrt(power(sin(radians((p.latitude-new.latitude)/2)),2)+cos(radians(new.latitude))*cos(radians(p.latitude))*power(sin(radians((p.longitude-new.longitude)/2)),2)))) <= p.matching_radius_km)
      or (lower(p.city)=lower(new.city) and lower(p.country)=lower(new.country))
    );
  return new;
end $$;
drop trigger if exists notify_matching_donors_trigger on public.blood_requests;
create trigger notify_matching_donors_trigger after insert on public.blood_requests for each row execute procedure public.notify_matching_donors();

-- Notify requester/donor when offers change.
create or replace function public.notify_response_change() returns trigger
language plpgsql security definer set search_path=public as $$
declare owner_id uuid; hosp text;
begin
  select created_by,hospital_name into owner_id,hosp from public.blood_requests where id=new.request_id;
  if tg_op='INSERT' then
    insert into public.notifications(user_id,title,body,href) values(owner_id,'A donor volunteered','A donor responded to your request for '||hosp,'#requests');
  elsif new.status is distinct from old.status and new.donor_id is not null then
    insert into public.notifications(user_id,title,body,href) values(new.donor_id,'Response updated','Your donor response is now '||new.status,'#requests');
    if new.status='accepted' then update public.blood_requests set status='matched',updated_at=now() where id=new.request_id and status='open'; end if;
  end if;
  return new;
end $$;
drop trigger if exists notify_response_change_trigger on public.donor_responses;
create trigger notify_response_change_trigger after insert or update of status on public.donor_responses for each row execute procedure public.notify_response_change();

-- Notify the other participant on chat message.
create or replace function public.notify_new_message() returns trigger
language plpgsql security definer set search_path=public as $$
declare donor uuid; owner_id uuid; target uuid;
begin
  select dr.donor_id,br.created_by into donor,owner_id from public.donor_responses dr join public.blood_requests br on br.id=dr.request_id where dr.id=new.response_id;
  target := case when new.sender_id=donor then owner_id else donor end;
  if target is not null then insert into public.notifications(user_id,title,body,href) values(target,'New private message','You have a new DonorLink coordination message','#requests'); end if;
  return new;
end $$;
drop trigger if exists notify_new_message_trigger on public.messages;
create trigger notify_new_message_trigger after insert on public.messages for each row execute procedure public.notify_new_message();

-- Nearby exact-group requests for the signed-in donor.
create or replace function public.nearby_requests_for_current_donor(p_radius_km integer default 25)
returns table(id uuid,blood_group text,component text,units integer,urgency text,hospital_name text,country text,city text,needed_by timestamptz,status text,is_verified boolean,distance_km numeric)
language sql security definer set search_path=public stable as $$
  with me as (select * from public.profiles where id=auth.uid() and role='donor')
  select r.id,r.blood_group,r.component,r.units,r.urgency,r.hospital_name,r.country,r.city,r.needed_by,r.status,r.is_verified,
    round((6371*2*asin(sqrt(power(sin(radians((r.latitude-me.latitude)/2)),2)+cos(radians(me.latitude))*cos(radians(r.latitude))*power(sin(radians((r.longitude-me.longitude)/2)),2))))::numeric,1)
  from public.blood_requests r,me
  where r.status in ('open','matched') and r.needed_by>now() and r.blood_group=me.blood_group
    and me.latitude is not null and me.longitude is not null and r.latitude is not null and r.longitude is not null
    and (6371*2*asin(sqrt(power(sin(radians((r.latitude-me.latitude)/2)),2)+cos(radians(me.latitude))*cos(radians(r.latitude))*power(sin(radians((r.longitude-me.longitude)/2)),2)))) <= least(greatest(p_radius_km,1),200)
  order by distance_km,r.needed_by;
$$;

-- Only admins can change organization trust state.
create or replace function public.admin_set_organization_status(p_org_id uuid,p_status text,p_note text default null)
returns void language plpgsql security definer set search_path=public as $$
begin
  if not exists(select 1 from public.profiles where id=auth.uid() and role='admin') then raise exception 'Admin access required'; end if;
  if p_status not in ('pending','verified','rejected','suspended') then raise exception 'Invalid status'; end if;
  update public.organizations set verification_status=p_status,verification_note=left(p_note,500),verified_at=case when p_status='verified' then now() else null end,updated_at=now() where id=p_org_id;
end $$;

-- Participant-safe contact disclosure: phone appears only after acceptance/completion.
create or replace function public.response_contact(p_response_id uuid)
returns table(full_name text,blood_group text,city text,phone text,status text)
language plpgsql security definer set search_path=public stable as $$
declare d uuid; o uuid; s text;
begin
  select dr.donor_id,br.created_by,dr.status into d,o,s from public.donor_responses dr join public.blood_requests br on br.id=dr.request_id where dr.id=p_response_id;
  if auth.uid() not in (d,o) then raise exception 'Not authorized'; end if;
  return query select p.full_name,p.blood_group,p.city,case when s in ('accepted','completed') then p.phone else null end,s from public.profiles p where p.id=d;
end $$;

-- Verified organization attached to the request can confirm a completed donation.
create or replace function public.confirm_verified_donation(p_response_id uuid)
returns text language plpgsql security definer set search_path=public as $$
declare org_id uuid; code text; req_id uuid; owner_id uuid; resp_status text;
begin
  select br.organization_id,br.id,dr.status into org_id,req_id,resp_status
  from public.donor_responses dr join public.blood_requests br on br.id=dr.request_id where dr.id=p_response_id;
  if org_id is null then raise exception 'Request has no verified organization'; end if;
  select o.owner_id into owner_id from public.organizations o where o.id=org_id and o.verification_status='verified';
  if owner_id is distinct from auth.uid() then raise exception 'Verified organization owner required'; end if;
  if resp_status not in ('accepted','completed') then raise exception 'Donor must first be accepted'; end if;
  insert into public.donation_confirmations(response_id,organization_id,confirmed_by,confirmed_at)
  values(p_response_id,org_id,auth.uid(),now())
  on conflict(response_id) do update set status='confirmed',confirmed_by=auth.uid(),confirmed_at=now()
  returning confirmation_code into code;
  update public.donor_responses set status='completed',updated_at=now() where id=p_response_id;
  return code;
end $$;

-- Safe self-deletion. Cascades remove linked profile/application data.
create or replace function public.delete_my_account()
returns void language plpgsql security definer set search_path=public,auth as $$
declare me uuid := auth.uid();
begin
  if me is null then raise exception 'Authentication required'; end if;
  delete from auth.users where id=me;
end $$;

alter table public.profiles enable row level security;
alter table public.organizations enable row level security;
alter table public.blood_requests enable row level security;
alter table public.donor_responses enable row level security;
alter table public.messages enable row level security;
alter table public.notifications enable row level security;
alter table public.donation_confirmations enable row level security;
alter table public.abuse_reports enable row level security;

-- Privileges are intentionally narrow.
revoke all on public.profiles from anon,authenticated;
grant select on public.profiles to authenticated;
grant update(full_name,country,city,blood_group,availability,phone,latitude,longitude,matching_radius_km,preferred_language,updated_at) on public.profiles to authenticated;

revoke all on public.organizations from anon,authenticated;
grant select on public.organizations to authenticated;
grant insert(owner_id,name,type,country,city,license_reference,website,contact_phone) on public.organizations to authenticated;

revoke all on public.blood_requests from anon,authenticated;
grant select on public.blood_requests to authenticated;
grant insert(created_by,organization_id,blood_group,component,units,urgency,hospital_name,country,city,latitude,longitude,needed_by,notes) on public.blood_requests to authenticated;
grant update(status,updated_at) on public.blood_requests to authenticated;

revoke all on public.donor_responses from anon,authenticated;
grant select on public.donor_responses to authenticated;
grant insert(request_id,donor_id,message) on public.donor_responses to authenticated;
grant update(status,message,updated_at) on public.donor_responses to authenticated;

revoke all on public.messages from anon,authenticated;
grant select on public.messages to authenticated;
grant insert(response_id,sender_id,body) on public.messages to authenticated;

revoke all on public.notifications from anon,authenticated;
grant select on public.notifications to authenticated;
grant update(is_read) on public.notifications to authenticated;

revoke all on public.donation_confirmations from anon,authenticated;
grant select on public.donation_confirmations to authenticated;

revoke all on public.abuse_reports from anon,authenticated;
grant insert(reporter_id,request_id,reason) on public.abuse_reports to authenticated;
grant select on public.abuse_reports to authenticated;

-- RLS policies.
drop policy if exists profiles_own_read on public.profiles;
drop policy if exists profiles_own_update on public.profiles;
create policy profiles_own_read on public.profiles for select to authenticated using(auth.uid()=id);
create policy profiles_own_update on public.profiles for update to authenticated using(auth.uid()=id) with check(auth.uid()=id);

drop policy if exists org_owner_verified_admin_read on public.organizations;
drop policy if exists org_owner_insert on public.organizations;
create policy org_owner_verified_admin_read on public.organizations for select to authenticated using(
  auth.uid()=owner_id or verification_status='verified' or exists(select 1 from public.profiles p where p.id=auth.uid() and p.role='admin')
);
create policy org_owner_insert on public.organizations for insert to authenticated with check(auth.uid()=owner_id);

drop policy if exists requests_authenticated_read on public.blood_requests;
drop policy if exists requests_owner_insert on public.blood_requests;
drop policy if exists requests_owner_update on public.blood_requests;
create policy requests_authenticated_read on public.blood_requests for select to authenticated using(true);
create policy requests_owner_insert on public.blood_requests for insert to authenticated with check(auth.uid()=created_by);
create policy requests_owner_update on public.blood_requests for update to authenticated using(auth.uid()=created_by) with check(auth.uid()=created_by);

drop policy if exists responses_participant_read on public.donor_responses;
drop policy if exists responses_donor_insert on public.donor_responses;
drop policy if exists responses_participant_update on public.donor_responses;
create policy responses_participant_read on public.donor_responses for select to authenticated using(
  auth.uid()=donor_id or exists(select 1 from public.blood_requests r where r.id=donor_responses.request_id and r.created_by=auth.uid())
);
create policy responses_donor_insert on public.donor_responses for insert to authenticated with check(auth.uid()=donor_id);
create policy responses_participant_update on public.donor_responses for update to authenticated using(
  auth.uid()=donor_id or exists(select 1 from public.blood_requests r where r.id=donor_responses.request_id and r.created_by=auth.uid())
);

drop policy if exists messages_participant_read on public.messages;
drop policy if exists messages_participant_insert on public.messages;
create policy messages_participant_read on public.messages for select to authenticated using(exists(
  select 1 from public.donor_responses dr join public.blood_requests br on br.id=dr.request_id
  where dr.id=messages.response_id and (dr.donor_id=auth.uid() or br.created_by=auth.uid()) and dr.status in ('accepted','completed')
));
create policy messages_participant_insert on public.messages for insert to authenticated with check(sender_id=auth.uid() and exists(
  select 1 from public.donor_responses dr join public.blood_requests br on br.id=dr.request_id
  where dr.id=messages.response_id and (dr.donor_id=auth.uid() or br.created_by=auth.uid()) and dr.status in ('accepted','completed')
));

drop policy if exists notifications_own_read on public.notifications;
drop policy if exists notifications_own_update on public.notifications;
create policy notifications_own_read on public.notifications for select to authenticated using(user_id=auth.uid());
create policy notifications_own_update on public.notifications for update to authenticated using(user_id=auth.uid()) with check(user_id=auth.uid());

drop policy if exists confirmations_participant_read on public.donation_confirmations;
create policy confirmations_participant_read on public.donation_confirmations for select to authenticated using(exists(
  select 1 from public.donor_responses dr join public.blood_requests br on br.id=dr.request_id join public.organizations o on o.id=donation_confirmations.organization_id
  where dr.id=donation_confirmations.response_id and (dr.donor_id=auth.uid() or br.created_by=auth.uid() or o.owner_id=auth.uid())
));

-- Explicit function privileges.
revoke all on function public.nearby_requests_for_current_donor(integer) from public;
grant execute on function public.nearby_requests_for_current_donor(integer) to authenticated;
revoke all on function public.admin_set_organization_status(uuid,text,text) from public;
grant execute on function public.admin_set_organization_status(uuid,text,text) to authenticated;
revoke all on function public.response_contact(uuid) from public;
grant execute on function public.response_contact(uuid) to authenticated;
revoke all on function public.confirm_verified_donation(uuid) from public;
grant execute on function public.confirm_verified_donation(uuid) to authenticated;
revoke all on function public.delete_my_account() from public;
grant execute on function public.delete_my_account() to authenticated;



drop policy if exists abuse_reporter_insert on public.abuse_reports;
drop policy if exists abuse_admin_read on public.abuse_reports;
create policy abuse_reporter_insert on public.abuse_reports for insert to authenticated with check(reporter_id=auth.uid());
create policy abuse_admin_read on public.abuse_reports for select to authenticated using(exists(select 1 from public.profiles p where p.id=auth.uid() and p.role='admin'));

create index if not exists idx_requests_open_location on public.blood_requests(status,country,city,blood_group,needed_by);
create index if not exists idx_profiles_donor_availability on public.profiles(role,blood_group,availability,country,city);
create index if not exists idx_responses_request on public.donor_responses(request_id,status);
create index if not exists idx_messages_response_time on public.messages(response_id,created_at);
create index if not exists idx_notifications_user_time on public.notifications(user_id,is_read,created_at desc);
create index if not exists idx_org_verification on public.organizations(verification_status,created_at);
create index if not exists idx_abuse_status on public.abuse_reports(status,created_at);
