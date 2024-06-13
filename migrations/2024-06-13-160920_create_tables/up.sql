create table public.users(
    id UUID PRIMARY KEY,
    username varchar not null unique,
    email varchar not null,
    password_hash varchar not null,
    full_name varchar null,
    otp_secret_encrypted varchar null,
    created_at timestamp not null default current_timestamp,
    updated_at timestamp not null default current_timestamp
);

create table public.sessions(
    id UUID PRIMARY KEY,
    user_id UUID not null,
    session_type varchar not null,
    refresh_time timestamp not null
);

--alter table public.sessions drop constraint sessions_user_id_fkey;
alter table public.sessions add constraint user_id_w_session_type unique (user_id,session_type);
