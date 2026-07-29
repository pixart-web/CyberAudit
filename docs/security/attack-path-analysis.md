# Attack path analysis

Attack paths representam hipóteses de alcance entre ativos com base em relações guardadas. Não executam autenticação, exploração, movimento lateral ou validação ofensiva.

A análise aplica tenant isolation, evita ciclos, limita profundidade e número de caminhos, e conserva factos versus inferências por passo. Cada candidato começa em `candidate` e pode ser validado, rejeitado ou arquivado por um reviewer autorizado.
