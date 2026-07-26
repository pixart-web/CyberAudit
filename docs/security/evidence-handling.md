# Tratamento de evidências

Evidências têm tenant, job, finding opcional, hash, tamanho, MIME, sensibilidade e origem. Authorization, cookies, tokens, passwords, API keys, sessões e parâmetros sensíveis são redigidos. Conteúdo de páginas é guardado apenas como excerto limitado. O preview web usa `<pre>` inerte; downloads exigem RBAC e devolvem `attachment`, `nosniff`, CSP `default-src 'none'; sandbox` e `private, no-store`.
