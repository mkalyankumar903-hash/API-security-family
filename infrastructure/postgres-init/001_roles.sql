-- Executed only once by the bootstrap superuser against an isolated development database.
CREATE ROLE api_family LOGIN PASSWORD 'api_family_dev' NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION;
GRANT CONNECT ON DATABASE api_family TO api_family;
GRANT USAGE, CREATE ON SCHEMA public TO api_family;

-- Dedicated queue owner and worker role. No superuser or BYPASSRLS privilege.
CREATE ROLE api_family_queue LOGIN PASSWORD 'api_family_worker_dev' NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION;
GRANT CONNECT ON DATABASE api_family TO api_family_queue;
