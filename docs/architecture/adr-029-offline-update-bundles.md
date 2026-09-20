# ADR-029 — Offline update bundle format and signing

Estado: aceite em 2026-09-20.

## Contexto

A secção 16 do pedido exige suporte a ambientes air-gapped: um formato de
bundle offline (`.caup`) para atualizações de aplicação, knowledge packs,
metadata de vulnerabilidades, threat intelligence e manifestos de modelo,
com manifesto assinado, checksums, verificação de compatibilidade,
provenance e — sobretudo — a garantia explícita de que "nunca confiar num
bundle offline só porque foi carregado manualmente".

## Decisão

### Formato

Um `.caup` é, nesta fase, um par `manifesto JSON + assinatura Ed25519`
(sem empacotamento zip próprio ainda). `UpdateManifest`
(`cyberaudit/update_bundle.py`) é um modelo pydantic com `bundle_id`,
`bundle_type` (`application_update` | `knowledge_pack` |
`vulnerability_metadata` | `threat_intelligence` | `model_manifest`),
`version`, `min/max_compatible_app_version`, `rollback_of`, `provenance` e
`checksums` (nome de ficheiro → SHA-256). `canonical_bytes()` serializa de
forma determinística (chaves ordenadas, sem espaços) — é exatamente esta
sequência de bytes que é assinada e verificada, nunca o JSON "como veio".

### Confiança nunca vem do upload

`TrustedKeyStore` só aceita chaves públicas Ed25519, configuradas pelo
administrador via `UPDATE_TRUSTED_PUBLIC_KEYS_PEM` (nunca dentro do
próprio bundle). `UpdateBundleService.validate()`:

1. Rejeita um manifesto malformado sem levantar exceção (devolve
   `BundleValidationResult(accepted=False, ...)`).
2. Verifica a assinatura contra cada chave confiada; sem nenhuma chave
   configurada, nada pode alguma vez ser aceite.
3. Verifica compatibilidade de versão (`app_version` da instalação contra
   `min/max_compatible_app_version`).
4. Verifica o SHA-256 de cada ficheiro referenciado no manifesto; um
   ficheiro em falta ou com hash diferente é motivo de rejeição.

Qualquer falha é acumulada em `reasons`; a aceitação exige zero falhas.

### O que fica fora desta fase

`UpdateBundleService` **valida**; nunca extrai, encena (`staging`), aplica
migrações, reinicia serviços ou executa rollback. Isso é responsabilidade
do instalador/runtime local (Fase 10.3.8), que permanece arquitetura-only
nesta fase — não existe ainda um `CyberAudit-Update-YYYY-MM.caup` real a
ser aplicado em produção. O endpoint `POST /api/v1/updates/validate`
existe apenas para relatar se um bundle *seria* aceite, com evento de
auditoria (`update_bundle.validated`) e o motivo de qualquer rejeição.

## Riscos e dívida

- Falta o empacotamento real (zip/tar assinado), extração para um
  diretório de staging e aplicação transacional com rollback.
- `model_manifest` como `bundle_type` prepara a integração futura com
  `AiModelManifest.manifest_signature` (ADR-026), mas essa ligação ainda
  não está implementada.
- Rotação de chaves de confiança e revogação não estão modeladas.
