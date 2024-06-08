// @generated automatically by Diesel CLI.

diesel::table! {
    sessions (user_id) {
        user_id -> Uuid,
        session_type -> Varchar,
        refresh_time -> Timestamp,
    }
}

diesel::table! {
    users (id) {
        id -> Uuid,
        username -> Varchar,
        email -> Varchar,
        password_hash -> Varchar,
        full_name -> Nullable<Varchar>,
        created_at -> Timestamp,
        updated_at -> Timestamp,
    }
}

diesel::allow_tables_to_appear_in_same_query!(
    sessions,
    users,
);
