-- ============================================================================
-- Garden Tracker v2 — Enable Row Level Security (RLS)
-- ----------------------------------------------------------------------------
-- WHY THIS EXISTS
--   Every table in this project is currently readable (and almost certainly
--   writable) by anyone using the public anon key that ships in index.html.
--   With RLS disabled, PostgREST lets the `anon`/`authenticated` roles touch
--   every row regardless of who owns it, so any visitor to the deployed site
--   can read every user's entire garden database.
--
-- WHAT THIS DOES
--   1. Turns RLS ON for every application table.
--   2. Adds one "owner only" policy per table, scoping rows to the signed-in
--      user via auth.uid(), following the ownership chain:
--          gardens / user_preferences      -> user_id            (direct)
--          locations / crops / todos        -> garden_id -> gardens.user_id
--          stage_history / water_log /       -> crop_id  -> crops.garden_id
--          feed_log / feed_schedules /                       -> gardens.user_id
--          harvests / notes
--   3. Adds indexes on the FK columns the policies traverse (no-ops if present).
--
-- SAFETY / HOW TO APPLY
--   * Review this before running. Enabling RLS with a wrong policy can lock the
--     live app out of its own data, so apply it to a Supabase *branch* first (or
--     during a quiet window) and confirm you can still sign in and see your data.
--   * The app authenticates with signInWithPassword, so authenticated requests
--     carry the user's JWT and auth.uid() resolves correctly. The anon key stays
--     public and is fine once these policies are in place.
--   * auth.uid() is wrapped in a scalar subquery `(select auth.uid())` so the
--     planner evaluates it once per statement instead of once per row.
--   * Re-runnable: each policy is dropped first, so applying twice is safe.
-- ============================================================================

begin;

-- ── Indexes the policies rely on (harmless if they already exist) ───────────
create index if not exists idx_gardens_user_id            on public.gardens(user_id);
create index if not exists idx_user_preferences_user_id   on public.user_preferences(user_id);
create index if not exists idx_locations_garden_id        on public.locations(garden_id);
create index if not exists idx_crops_garden_id            on public.crops(garden_id);
create index if not exists idx_todos_garden_id            on public.todos(garden_id);
create index if not exists idx_stage_history_crop_id      on public.stage_history(crop_id);
create index if not exists idx_water_log_crop_id          on public.water_log(crop_id);
create index if not exists idx_feed_log_crop_id           on public.feed_log(crop_id);
create index if not exists idx_feed_schedules_crop_id     on public.feed_schedules(crop_id);
create index if not exists idx_harvests_crop_id           on public.harvests(crop_id);
create index if not exists idx_notes_crop_id              on public.notes(crop_id);

-- ── Enable RLS on every table ───────────────────────────────────────────────
alter table public.gardens          enable row level security;
alter table public.user_preferences enable row level security;
alter table public.locations        enable row level security;
alter table public.crops            enable row level security;
alter table public.todos            enable row level security;
alter table public.stage_history    enable row level security;
alter table public.water_log        enable row level security;
alter table public.feed_log         enable row level security;
alter table public.feed_schedules   enable row level security;
alter table public.harvests         enable row level security;
alter table public.notes            enable row level security;

-- ── Direct-ownership tables (user_id column) ────────────────────────────────
drop policy if exists "own gardens" on public.gardens;
create policy "own gardens" on public.gardens
  for all to authenticated
  using ( user_id = (select auth.uid()) )
  with check ( user_id = (select auth.uid()) );

drop policy if exists "own preferences" on public.user_preferences;
create policy "own preferences" on public.user_preferences
  for all to authenticated
  using ( user_id = (select auth.uid()) )
  with check ( user_id = (select auth.uid()) );

-- ── Garden-scoped tables (garden_id -> gardens.user_id) ─────────────────────
drop policy if exists "own locations" on public.locations;
create policy "own locations" on public.locations
  for all to authenticated
  using ( exists (
    select 1 from public.gardens g
    where g.id = locations.garden_id and g.user_id = (select auth.uid())
  ))
  with check ( exists (
    select 1 from public.gardens g
    where g.id = locations.garden_id and g.user_id = (select auth.uid())
  ));

drop policy if exists "own crops" on public.crops;
create policy "own crops" on public.crops
  for all to authenticated
  using ( exists (
    select 1 from public.gardens g
    where g.id = crops.garden_id and g.user_id = (select auth.uid())
  ))
  with check ( exists (
    select 1 from public.gardens g
    where g.id = crops.garden_id and g.user_id = (select auth.uid())
  ));

drop policy if exists "own todos" on public.todos;
create policy "own todos" on public.todos
  for all to authenticated
  using ( exists (
    select 1 from public.gardens g
    where g.id = todos.garden_id and g.user_id = (select auth.uid())
  ))
  with check ( exists (
    select 1 from public.gardens g
    where g.id = todos.garden_id and g.user_id = (select auth.uid())
  ));

-- ── Crop-scoped tables (crop_id -> crops.garden_id -> gardens.user_id) ──────
-- Helper predicate is inlined per table so each policy is self-contained.
drop policy if exists "own stage_history" on public.stage_history;
create policy "own stage_history" on public.stage_history
  for all to authenticated
  using ( exists (
    select 1 from public.crops c
    join public.gardens g on g.id = c.garden_id
    where c.id = stage_history.crop_id and g.user_id = (select auth.uid())
  ))
  with check ( exists (
    select 1 from public.crops c
    join public.gardens g on g.id = c.garden_id
    where c.id = stage_history.crop_id and g.user_id = (select auth.uid())
  ));

drop policy if exists "own water_log" on public.water_log;
create policy "own water_log" on public.water_log
  for all to authenticated
  using ( exists (
    select 1 from public.crops c
    join public.gardens g on g.id = c.garden_id
    where c.id = water_log.crop_id and g.user_id = (select auth.uid())
  ))
  with check ( exists (
    select 1 from public.crops c
    join public.gardens g on g.id = c.garden_id
    where c.id = water_log.crop_id and g.user_id = (select auth.uid())
  ));

drop policy if exists "own feed_log" on public.feed_log;
create policy "own feed_log" on public.feed_log
  for all to authenticated
  using ( exists (
    select 1 from public.crops c
    join public.gardens g on g.id = c.garden_id
    where c.id = feed_log.crop_id and g.user_id = (select auth.uid())
  ))
  with check ( exists (
    select 1 from public.crops c
    join public.gardens g on g.id = c.garden_id
    where c.id = feed_log.crop_id and g.user_id = (select auth.uid())
  ));

drop policy if exists "own feed_schedules" on public.feed_schedules;
create policy "own feed_schedules" on public.feed_schedules
  for all to authenticated
  using ( exists (
    select 1 from public.crops c
    join public.gardens g on g.id = c.garden_id
    where c.id = feed_schedules.crop_id and g.user_id = (select auth.uid())
  ))
  with check ( exists (
    select 1 from public.crops c
    join public.gardens g on g.id = c.garden_id
    where c.id = feed_schedules.crop_id and g.user_id = (select auth.uid())
  ));

drop policy if exists "own harvests" on public.harvests;
create policy "own harvests" on public.harvests
  for all to authenticated
  using ( exists (
    select 1 from public.crops c
    join public.gardens g on g.id = c.garden_id
    where c.id = harvests.crop_id and g.user_id = (select auth.uid())
  ))
  with check ( exists (
    select 1 from public.crops c
    join public.gardens g on g.id = c.garden_id
    where c.id = harvests.crop_id and g.user_id = (select auth.uid())
  ));

drop policy if exists "own notes" on public.notes;
create policy "own notes" on public.notes
  for all to authenticated
  using ( exists (
    select 1 from public.crops c
    join public.gardens g on g.id = c.garden_id
    where c.id = notes.crop_id and g.user_id = (select auth.uid())
  ))
  with check ( exists (
    select 1 from public.crops c
    join public.gardens g on g.id = c.garden_id
    where c.id = notes.crop_id and g.user_id = (select auth.uid())
  ));

commit;

-- ============================================================================
-- POST-APPLY VERIFICATION (run these AFTER applying, as a signed-out check):
--   With only the anon key and no user session, this must now return 0 rows /
--   permission-denied instead of real data:
--       select * from public.crops limit 1;
--   And a signed-in user must still see ONLY their own rows.
-- ============================================================================
