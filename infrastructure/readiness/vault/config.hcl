ui = true
disable_mlock = true

storage "file" {
  path = "/vault/data"
}

listener "tcp" {
  address = "0.0.0.0:8200"
  tls_cert_file = "/run/tls/service.crt"
  tls_key_file = "/run/tls/private/service.key"
  tls_client_ca_file = "/run/tls/ca.crt"
}

api_addr = "https://vault:8200"
cluster_addr = "https://vault:8201"
