/** Schema of an engagement database. One file per engagement. */
export const ENGAGEMENT_SCHEMA = `
create table if not exists meta (
  key   text primary key,
  value text not null
);

create table if not exists entities (
  id            text primary key,
  kind          text not null,
  natural_key   text not null,
  attributes    text not null,
  human_fields  text not null default '{}',
  conflicts     text not null default '[]',
  tags          text not null default '[]',
  out_of_scope  integer not null default 0,
  created_at    text not null,
  created_by    text not null,
  updated_at    text not null,
  revision      integer not null default 0,
  deleted_at    text,
  -- The scope address of a plugin entity, kept by the core so scope still applies while its plugin is off.
  scope_target  text,
  unique (kind, natural_key)
);
create index if not exists entities_kind on entities (kind, updated_at);

create table if not exists edges (
  id          text primary key,
  type        text not null,
  from_kind   text not null,
  from_id     text not null,
  to_kind     text not null,
  to_id       text not null,
  attributes  text,
  first_seen  text not null,
  last_seen   text not null,
  deleted_at  text,
  unique (type, from_id, to_id)
);
create index if not exists edges_from on edges (from_id);
create index if not exists edges_to on edges (to_id);

create table if not exists sightings (
  id            text primary key,
  subject_type  text not null,
  subject_id    text not null,
  attributes    text not null,
  source        text not null,
  raw_id        text,
  run_id        text,
  confidence    real not null,
  observed_at   text not null,
  created_at    text not null
);
create index if not exists sightings_subject on sightings (subject_id);

create table if not exists runs (
  id          text primary key,
  actor       text not null,
  origin      text not null,
  tool        text,
  command     text,
  targets     text not null,
  risk        text not null,
  policy      text not null,
  runner      text not null,
  status      text not null,
  started_at  text not null,
  ended_at    text,
  exit_code   integer,
  raw_ids     text not null default '[]',
  summary     text,
  -- MITRE ATT&CK techniques the run exercises.
  attack      text
);
create index if not exists runs_started on runs (started_at);

create table if not exists raw_artifacts (
  sha256         text primary key,
  type           text not null,
  mime           text not null,
  size           integer not null,
  run_id         text,
  original_name  text,
  stored_at      text not null
);

create table if not exists audit_events (
  seq           integer primary key,
  at            text not null,
  actor         text not null,
  action        text not null,
  subject       text,
  payload_hash  text not null,
  prev_hash     text not null,
  hash          text not null
);
`;

export const WORKSPACE_SCHEMA = `
create table if not exists clients (
  id          text primary key,
  name        text not null unique,
  created_at  text not null
);

create table if not exists engagements (
  id          text primary key,
  client_id   text not null references clients (id),
  name        text not null,
  mode        text not null,
  status      text not null,
  created_at  text not null,
  -- The folder the project lives in (any folder the operator chose).
  dir         text not null
);

create table if not exists operators (
  id          text primary key,
  name        text not null unique,
  role        text not null,
  token_hash  text not null unique,
  created_at  text not null,
  disabled    integer not null default 0
);
`;
