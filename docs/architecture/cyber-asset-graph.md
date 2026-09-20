# Cyber Asset Graph

O grafo liga ativos, IPs, serviços, software, vulnerabilidades, findings, ambientes, zonas e redes sem criar uma segunda fonte de verdade.

`PostgreSQLAssetGraphRepository` aplica sempre `organization_id`, limites progressivos e filtros. `CyberAssetGraphService` entrega nós e relações à API. A interface mostra uma vista limitada e acessível; expansão massiva exige filtros adicionais.

Relações guardam fonte, confiança e estado de revisão. Descobertas automáticas não promovem sugestões a ativos. `AttackPathAnalysisService` usa BFS com proteção contra ciclos, profundidade e quantidade máximas. Os resultados são candidatos analíticos, não provas de exploração.

Uma graph database poderá substituir apenas a implementação do repository, mantendo PostgreSQL como system of record.
