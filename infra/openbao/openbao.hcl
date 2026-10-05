ui            = false
disable_mlock = true

storage "raft" {
  path    = "/openbao/data"
  node_id = "andyur-openbao-dev"
}

listener "tcp" {
  address                  = "0.0.0.0:8200"
  cluster_address          = "0.0.0.0:8201"
  tls_cert_file            = "/openbao/tls/server.crt"
  tls_key_file             = "/openbao/tls/server.key"
  tls_client_ca_file       = "/openbao/tls/ca.crt"
  tls_min_version          = "tls13"
  tls_disable_client_certs = true
}

api_addr     = "https://openbao:8200"
cluster_addr = "https://openbao:8201"

audit "file" "stdout" {
  description = "Structured development audit stream"
  options {
    file_path = "/dev/stdout"
    log_raw   = "false"
    mode      = "0000"
  }
}
