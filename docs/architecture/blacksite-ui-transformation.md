# CYBERAUDIT // BLACKSITE

Estado: transformação visual em curso na branch desktop-first.

## Auditoria da interface existente

O frontend possui 102 rotas de produção, uma `Shell` partilhada, componentes de
estado acessíveis, páginas de recursos genéricas e workspaces ligados à API. A
arquitetura de informação, os contratos HTTP e os controlos RBAC já estão
estabelecidos e devem ser preservados.

### Padrões a preservar

- rotas, labels de navegação e deep links existentes;
- pesquisa global com endpoints tenant-scoped;
- paleta de navegação com destinos allowlisted;
- estados de loading, vazio e erro;
- escala semântica de severidade, com ícone e texto;
- workspaces de auditoria, findings, jobs e Asset Graph ligados à API;
- dark mode, foco visível e navegação por teclado;
- shell same-origin usada pelo runtime Tauri.

### Padrões a substituir

- sidebar longa com todos os destinos permanentemente expostos;
- grelha de cartões SaaS com baixa densidade operacional;
- tipografia Inter e verde saturado como decoração;
- raios e sombras excessivos em contentores de dados;
- métricas isoladas em cartões idênticos;
- inspeção contextual abaixo do conteúdo em vez de num painel lateral;
- Asset Graph apresentado como grelha de nós sem ligações visuais.

## Sistema visual

- tema único escuro;
- IBM Plex Sans para interface e IBM Plex Mono para dados técnicos;
- fundo `#080D13`, superfície `#101922`, superfície secundária `#14232D`;
- border técnico `#273B43`, texto `#F0F5F6`, texto muted `#8299A1`;
- teal de sinal `#8FE6CC`, crítico `#FF887E`, warning `#F2BD74`;
- cantos entre 4 e 8 px, reservando pills para estados;
- movimento apenas para feedback e transições de estado;
- números e identificadores sempre em mono;
- severidade usada apenas com significado semântico.

## Plano por rotas

### Fundações

- todas as rotas autenticadas: nova shell workstation, rail compacto,
  navegação por grupos, command bar, contexto de organização/auditoria e estado
  local do runtime;
- componentes partilhados: superfícies mais planas, tabelas densas, estados e
  painéis de inspeção consistentes;
- login: aplicar tokens e tipografia sem alterar o fluxo de autenticação.

### Workspaces prioritários

- `/dashboard`: command deck com dados reais de postura, ativos, findings,
  auditorias, atividade, jobs e adaptadores;
- `/findings`: workbench denso com pesquisa, filtros, ordenação, seleção por
  teclado e inspector contextual;
- `/findings/[id]`: detalhe técnico com evidência, impacto, remediação e reteste;
- `/engagements` e `/engagements/[id]`: lista e workspace operacional;
- `/asset-graph`: canvas relacional a partir de nós e edges reais, zoom,
  seleção e inspector;
- `/jobs` e `/jobs/[id]`: recebem o sistema visual através dos primitives
  partilhados e da shell.

### Restantes módulos

As páginas que usam `ResourcePage`, `Card`, `Tabs`, `MetricCard` ou `Shell`
recebem automaticamente a nova linguagem. Ajustes específicos ficam limitados
a inconsistências observadas na QA visual, sem mudar contratos ou navegação.

## Restrições

- nenhum dado, finding, evento ou estado live será fabricado;
- nenhuma relação será criada fora do payload real do Asset Graph;
- nenhuma biblioteca de UI adicional será introduzida;
- nenhuma ferramenta ofensiva, terminal ou comando arbitrário será exposto;
- o runtime local, proxy same-origin e packaging Tauri permanecem inalterados.
