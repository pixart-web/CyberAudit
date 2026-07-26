# Isolamento do worker

Na Fase 2 o adaptador fictício executa no processo worker porque não possui capacidades externas. A abstração `ExecutionSandboxConfig` prepara:

- filesystem read-only;
- diretório efémero abstrato;
- limites de CPU, memória e processos;
- rede `none` por defeito;
- destinations permitidos;
- timeout;
- allowlist de ambiente vazia.

Adaptadores futuros com rede ou ferramentas reais deverão executar em contentores efémeros sem shell genérico, com imagem imutável, seccomp/AppArmor, utilizador sem privilégios, filesystem read-only e egress allowlisted após resolução DNS.

O worker volta a validar perfil, configuração, aprovação, alvo e `ScopePolicyEngine` imediatamente antes da execução. Uma falha produz `FAILED_POLICY_REVALIDATION` e o adapter não é invocado.
