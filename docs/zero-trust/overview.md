# Zero Trust

O motor avalia Identity, Device, Session, Application, Network, Workload, Data
e Control Trust. Cada dimensão expõe score, peso, confiança, fatores,
evidências e fatores desconhecidos.

O cálculo é determinístico e versionado. Valores desconhecidos não penalizam o
score observado, mas reduzem a confiança; confiança inferior a 35% produz
`insufficient_evidence`. Recomendações são advisory e nunca executam ações.
