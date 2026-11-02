-- Run once using the Supabase SQL editor. This private prototype store is accessed
-- only through the Python server. Client/anon/authenticated roles have no access.
create table if not exists public.target_state (
  id integer primary key check (id = 1),
  revision bigint not null,
  payload jsonb not null
);
alter table public.target_state enable row level security;
revoke all on public.target_state from public, anon, authenticated;
grant all on public.target_state to service_role;

create or replace function public.target_read_state() returns jsonb
language sql security invoker set search_path = public
as $$ select jsonb_build_object('revision', revision, 'payload', payload)
      from public.target_state where id = 1 $$;

create or replace function public.target_write_state(expected_revision bigint, new_payload jsonb)
returns boolean language plpgsql security invoker set search_path = public
as $$
begin
  if expected_revision = 0 then
    insert into public.target_state values (1, 1, new_payload) on conflict do nothing;
  else
    update public.target_state set payload = new_payload, revision = revision + 1
      where id = 1 and revision = expected_revision;
  end if;
  return found;
end $$;
revoke all on function public.target_read_state() from public, anon, authenticated;
revoke all on function public.target_write_state(bigint,jsonb) from public, anon, authenticated;
grant execute on function public.target_read_state() to service_role;
grant execute on function public.target_write_state(bigint,jsonb) to service_role;
