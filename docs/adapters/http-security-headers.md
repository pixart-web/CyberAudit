# HTTP security headers

`cyberaudit.http_security_headers` usa `HEAD` e um `GET` limitado apenas quando HEAD devolve 405/501. Analisa headers e atributos de cookies, nunca valores. HSTS, CSP e outros controlos recebem severidade contextual. Redirects são resolvidos e revalidados antes de qualquer nova ligação.
