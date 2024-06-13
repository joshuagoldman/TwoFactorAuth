ALTER TABLE public.sessions ADD CONSTRAINT unique_by_id_type UNIQUE (user_id,session_type);
