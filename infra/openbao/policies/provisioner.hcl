path "secret/data/development/authorization-servers/+/admin" {
  capabilities = ["read"]
}
path "secret/data/development/authorization-servers/+/andyur-client" {
  capabilities = ["create", "update", "read"]
}
path "secret/metadata/development/authorization-servers/+/andyur-client" {
  capabilities = ["read"]
}
path "transit/datakey/plaintext/tofu-state" {
  capabilities = ["update"]
}
path "transit/decrypt/tofu-state" {
  capabilities = ["update"]
}
