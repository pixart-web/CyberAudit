path "cyberaudit/data/organizations/*" {
  capabilities = ["read"]
}

path "cyberaudit/metadata/organizations/*" {
  capabilities = ["read"]
}

path "sys/health" {
  capabilities = ["read"]
}
