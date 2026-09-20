# Credential Handling

A API aceita exclusivamente referências `vault://`, `aws-secrets://`,
`azure-key-vault://`, `gcp-secret://` ou `development://demo-*`. O valor
referenciado nunca é devolvido pela API nem incluído no audit log.

Produção deve resolver a referência no boundary do connector, com identidade
de workload, rotação, least privilege e redaction estruturada. O esquema de
desenvolvimento só pode apontar para dados sintéticos.
