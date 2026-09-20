# Segurança dos dados SOC

- O tenant vem do JWT e nunca do evento submetido.
- Chaves não declaradas são descartadas.
- Tokens, passwords, API keys e cabeçalhos Authorization conhecidos são
  removidos antes da persistência normalizada.
- IDs externos são únicos por tenant/origem e fingerprints impedem alertas
  duplicados.
- Conteúdo é não confiável, nunca HTML e nunca executado.
- Hunts e regras não aceitam SQL, regex fornecida livremente, scripts ou
  expressões.
- IOCs incluem hash, confiança, proveniência e expiração.
- Objetos de data lake são privados, classificados, cifrados por contrato e
  sujeitos a retenção/legal hold.
- Métricas usam apenas labels de baixa cardinalidade; não contêm IDs pessoais,
  tokens nem payloads.
