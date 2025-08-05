--- Initialize separate database for each microservice
--- This script when postgresql container start for the first time


CREATE DATABASE notesverb_auth;
CREATE DATABASE notesverb_users;
CREATE DATABASE notesverb_notes;

create DATABASE notesverb_tags;

CREATE ROLE "user" WITH LOGIN PASSWORD 'password';
CREATE DATABASE notesverb OWNER "user";
GRANT ALL PRIVILEGES ON DATABASE notesverb TO "user";

GRANT ALL PRIVILEGES ON DATABASE notesverb_auth TO "user";
GRANT ALL PRIVILEGES ON DATABASE notesverb_users TO "user";
GRANT ALL PRIVILEGES ON DATABASE notesverb_notes TO "user";
GRANT ALL PRIVILEGES ON DATABASE notesverb_tags TO "user";