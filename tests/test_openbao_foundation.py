from pathlib import Path


ROOT = Path(__file__).parents[1]
BAO = ROOT / "infra" / "openbao"


def test_openbao_image_and_network_are_immutable_and_isolated():
    compose = (BAO / "compose.yaml").read_text()
    assert "openbao/openbao@sha256:" in compose
    assert ":latest" not in compose
    assert '127.0.0.1:${ANDYUR_OPENBAO_PORT:-8200}:8200' in compose
    assert "internal: true" in compose
    assert 'cap_drop: ["ALL"]' in compose
    assert "no-new-privileges:true" in compose
    assert "read_only: true" in compose
    assert 'cap_add: ["CHOWN", "FOWNER"]' in compose
    assert "condition: service_completed_successfully" in compose


def test_openbao_listener_requires_tls13_and_audits_without_raw_values():
    config = (BAO / "openbao.hcl").read_text()
    assert 'tls_min_version          = "tls13"' in config
    assert 'tls_disable_client_certs = true' in config
    assert 'log_raw   = "false"' in config
    assert 'storage "raft"' in config


def test_policies_separate_provisioning_certification_and_runtime():
    policies = {path.stem: path.read_text() for path in (BAO / "policies").glob("*.hcl")}
    assert set(policies) == {"provisioner", "certifier", "runtime-as", "model-broker"}
    assert "production" not in policies["provisioner"]
    assert "admin" not in policies["runtime-as"]
    assert "transit/sign/as-certification" in policies["certifier"]
    for policy in policies.values():
        assert '"sudo"' not in policy
        assert 'path "*"' not in policy
        assert 'capabilities = ["read", "create", "update", "delete", "list", "sudo"]' not in policy


def test_bootstrap_requires_external_empty_recovery_directory_and_no_dev_mode():
    script = (BAO / "openbao-stack.sh").read_text()
    assert "ANDYUR_OPENBAO_RECOVERY_DIR" in script
    assert "recovery directory must be empty" in script
    assert "-key-shares=3 -key-threshold=2" in script
    assert "server -dev" not in script
    assert "--confirm-destroy-development-vault" in script


def test_configuration_receives_root_only_on_stdin_and_separates_policies():
    configure = (BAO / "configure.sh").read_text()
    stack = (BAO / "openbao-stack.sh").read_text()
    assert "IFS= read -r BAO_TOKEN" in configure
    assert "exportable=false" in configure
    assert "allow_plaintext_backup=false" in configure
    assert "type=aes256-gcm96" in configure
    assert "auto_rotate_period=720h" in configure
    assert "printf '%s\\n' \"$token\" | compose exec -T" in stack
    assert "-e BAO_TOKEN" not in stack


def test_opentofu_example_uses_openbao_and_enforces_state_and_plan():
    encryption = (BAO / "opentofu-encryption.hcl.example").read_text()
    assert 'key_provider "openbao"' in encryption
    assert 'key_name                 = "tofu-state"' in encryption
    assert encryption.count("enforced = true") == 2
    assert "token" not in encryption
    provisioner = (BAO / "policies" / "provisioner.hcl").read_text()
    assert 'path "transit/datakey/plaintext/tofu-state"' in provisioner
    assert 'path "transit/decrypt/tofu-state"' in provisioner
