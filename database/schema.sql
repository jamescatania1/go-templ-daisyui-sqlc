CREATE TABLE public.email_verifications (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id uuid NOT NULL,
    created_at timestamp with time zone NOT NULL DEFAULT now()
);

CREATE TABLE public.refresh_tokens (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id uuid NOT NULL,
    token character varying NOT NULL,
    created_at timestamp with time zone NOT NULL DEFAULT now(),
    expires_at timestamp with time zone NOT NULL
);

CREATE TABLE public.users (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    email character varying NOT NULL UNIQUE,
    name character varying NOT NULL,
    password_hash character varying NOT NULL,
    created_at timestamp with time zone NOT NULL DEFAULT now(),
    email_verified boolean DEFAULT false NOT NULL
);

CREATE INDEX "fki_FK_email_verifications_users" ON public.email_verifications USING btree (user_id);

CREATE INDEX "fki_FK_refresh_tokens_users" ON public.refresh_tokens USING btree (user_id);


ALTER TABLE ONLY public.email_verifications
    ADD CONSTRAINT "FK_email_verifications_users" FOREIGN KEY (user_id) REFERENCES public.users(id) NOT VALID;

ALTER TABLE ONLY public.refresh_tokens
    ADD CONSTRAINT "FK_refresh_tokens_users" FOREIGN KEY (user_id) REFERENCES public.users(id) NOT VALID;
