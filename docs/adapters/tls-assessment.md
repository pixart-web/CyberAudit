# TLS assessment

`cyberaudit.tls_assessment` abre uma ligação TLS ao IP resolvido e fixado, usando SNI autorizado. Recolhe certificado DER, fingerprint SHA-256, subject, issuer, SAN, validade, versão e cipher negociada. A tentativa verificada é seguida por inspeção sem confiança apenas quando necessária para documentar uma cadeia inválida. Não testa downgrades, renegociação ou listas de ciphers.
