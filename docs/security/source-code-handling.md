# Source Code Handling

The API stores repository metadata only. It does not clone repositories, run
hooks, invoke interpreters, install packages or accept arbitrary paths. Imported
documents are private, size-limited and treated as untrusted bytes.

Future SCM ingestion must use short-lived app credentials, immutable revisions,
read-only mounts and disposable runners without access to the API database.
