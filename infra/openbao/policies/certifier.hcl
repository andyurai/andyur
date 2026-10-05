path "secret/data/development/authorization-servers/+/andyur-client" {
  capabilities = ["read"]
}
path "secret/data/development/authorization-servers/+/test-user" {
  capabilities = ["read"]
}
path "transit/sign/as-certification" {
  capabilities = ["update"]
}
path "transit/keys/as-certification" {
  capabilities = ["read"]
}
