create table public.users(
    id UUID PRIMARY KEY,
    username varchar not null unique,
    email varchar not null,
    password_hash varchar not null,
    full_name varchar not null,
    created_at timestamp not null default current_timestamp,
    updated_at timestamp not null default current_timestamp
);

create table public.sessions(
    user_id UUID PRIMARY KEY,
    session_type varchar not null,
    refresh_time timestamp not null
);
