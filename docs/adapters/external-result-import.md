# Importação de resultados externos

Formatos: JSON/CSV CyberAudit, SARIF 2.x, CycloneDX JSON e XML CyberAudit. Uploads ficam privados, têm extensão/MIME/tamanho verificados e SHA-256. XML usa `defusedxml`; DTD e entidades são rejeitadas. O utilizador revê um preview sanitizado antes da confirmação. Findings ficam `imported=true`, `simulated=false` e `verification_status=unverified`.
