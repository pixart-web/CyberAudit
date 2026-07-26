# SecureHttpClient

O cliente central valida scheme, hostname IDNA, credenciais embutidas e porta. DNS é resolvido antes da ligação, os IPs são classificados, e a ligação é aberta diretamente ao IP fixado preservando Host/SNI. Respostas, tempo, taxa, pedidos e redirects têm limites imutáveis calculados no backend. O cliente envia `Accept-Encoding: identity`, fecha a ligação e nunca executa conteúdo.
