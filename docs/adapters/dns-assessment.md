# DNS assessment

`cyberaudit.dns_assessment` consulta A, AAAA, CNAME, MX, NS, TXT, CAA, SOA e DNSKEY para o nome exato. Existe cache por job, timeout e máximo de 12 consultas. Não há enumeração ou brute force. Resoluções são classificadas pela política de rede; um IP fora da autorização não se torna um novo alvo.
