insert into users (email, password_hash, role, mfa_enabled)
values ('owner@example.com', 'replace-with-real-hash', 'owner', false)
returning id, email, role;
