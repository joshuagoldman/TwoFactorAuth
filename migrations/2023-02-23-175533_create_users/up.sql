create table public.users(
    id UUID PRIMARY KEY,
    username varchar not null unique,
    email varchar not null,
    password_hash varchar not null,
    full_name varchar null,
    otp_secret_encrypted varchar null,
    created_at timestamp not null default current_timestamp,
    updated_at timestamp not null default current_timestamp
)
