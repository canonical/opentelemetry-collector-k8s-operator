# Copyright 2026 Canonical Ltd.
# See LICENSE file for licensing details.

"""Unit tests for external-config integration functionality.

NOTE: These tests focus on the charm's handling of external configs.
Basic validation (config_yaml is valid YAML, pipelines is a valid list) is
already handled by OtelcolIntegratorRelationData in the otelcol-integrator library.
Therefore, we don't test for missing keys or invalid YAML here - the library
guarantees those cases won't reach our code.

We test:
- Directory and file management
- Internal YAML structure validation (dict of components)
- Component type validation
- Configuration merging logic
"""

from unittest.mock import MagicMock, patch

import yaml
from ops.testing import Relation, State

from src.constants import EXTERNAL_CONFIG_SECRETS_DIR


def test_external_config_directory_created(ctx, otelcol_container):
    """Test that external config secrets directory is created when needed."""
    # GIVEN an external-config relation with secret files
    external_config_rel = Relation(
        "external-config",
        remote_app_data={
            "config": yaml.safe_dump([
                {
                    "config_yaml": yaml.safe_dump({"receivers": {"test": {}}}),
                    "pipelines": ["metrics"],
                    "secret_files": {f"{EXTERNAL_CONFIG_SECRETS_DIR}/secret.txt": "secret"},
                }
            ])
        },
    )

    state = State(relations=[external_config_rel], containers=otelcol_container, leader=True)

    # WHEN the charm processes the relation
    with patch("integrations.OtelcolIntegratorRequirer") as mock_requirer_class:
        mock_requirer = MagicMock()
        mock_requirer.retrieve_external_configs.return_value = [
            {
                "config_yaml": yaml.safe_dump({"receivers": {"test": {}}}),
                "pipelines": ["metrics"],
            }
        ]
        mock_requirer.secret_files = {f"{EXTERNAL_CONFIG_SECRETS_DIR}/secret.txt": "secret"}
        mock_requirer_class.return_value = mock_requirer

        out = ctx.run(ctx.on.relation_changed(external_config_rel), state)

    # THEN the external config directory is created
    container = out.get_container("otelcol")
    fs = container.get_filesystem(ctx)
    secrets_dir = fs.joinpath(EXTERNAL_CONFIG_SECRETS_DIR.lstrip("/"))
    assert secrets_dir.exists()


def test_external_config_directory_removed_when_no_secrets(ctx, otelcol_container):
    """Test that external config directory is removed when there are no secrets."""
    # GIVEN an external-config relation without secret files
    external_config_rel = Relation(
        "external-config",
        remote_app_data={
            "config": yaml.safe_dump([
                {
                    "config_yaml": yaml.safe_dump({"receivers": {"test": {}}}),
                    "pipelines": ["metrics"],
                }
            ])
        },
    )

    state = State(relations=[external_config_rel], containers=otelcol_container, leader=True)

    # WHEN the charm processes the relation
    with patch("integrations.OtelcolIntegratorRequirer") as mock_requirer_class:
        mock_requirer = MagicMock()
        mock_requirer.retrieve_external_configs.return_value = [
            {
                "config_yaml": yaml.safe_dump({"receivers": {"test": {}}}),
                "pipelines": ["metrics"],
            }
        ]
        mock_requirer.secret_files = {}
        mock_requirer_class.return_value = mock_requirer

        out = ctx.run(ctx.on.relation_changed(external_config_rel), state)

    # THEN the external config directory is removed (if it existed)
    container = out.get_container("otelcol")
    fs = container.get_filesystem(ctx)
    secrets_dir = fs.joinpath(EXTERNAL_CONFIG_SECRETS_DIR.lstrip("/"))
    # Directory should not exist or should have been removed
    assert not secrets_dir.exists()


def test_external_config_secrets_written_to_disk(ctx, otelcol_container):
    """Test that secret files are written to the container filesystem."""
    # GIVEN an external-config relation with secret files
    secret_content = "super-secret-token-12345"
    secret_path = f"{EXTERNAL_CONFIG_SECRETS_DIR}/auth_token.txt"

    external_config_rel = Relation(
        "external-config",
        remote_app_data={
            "config": yaml.safe_dump([
                {
                    "config_yaml": yaml.safe_dump({
                        "receivers": {
                            "custom": {
                                "auth_token_file": secret_path
                            }
                        }
                    }),
                    "pipelines": ["metrics"],
                    "secret_files": {secret_path: secret_content},
                }
            ])
        },
    )

    state = State(relations=[external_config_rel], containers=otelcol_container, leader=True)

    # WHEN the charm processes the relation
    with patch("integrations.OtelcolIntegratorRequirer") as mock_requirer_class:
        mock_requirer = MagicMock()
        mock_requirer.retrieve_external_configs.return_value = [
            {
                "config_yaml": yaml.safe_dump({
                    "receivers": {"custom": {"auth_token_file": secret_path}}
                }),
                "pipelines": ["metrics"],
            }
        ]
        mock_requirer.secret_files = {secret_path: secret_content}
        mock_requirer_class.return_value = mock_requirer

        out = ctx.run(ctx.on.relation_changed(external_config_rel), state)

    # THEN the secret file is written to the filesystem
    container = out.get_container("otelcol")
    fs = container.get_filesystem(ctx)
    secret_file = fs.joinpath(secret_path.lstrip("/"))
    assert secret_file.exists()
    written_content = secret_file.read_text()
    assert written_content == secret_content


def test_external_config_merged_into_otel_config(config_manager):
    """Test that external config is properly merged into the OTel configuration."""
    # GIVEN a ConfigManager instance
    external_configs = [
        {
            "config_yaml": yaml.safe_dump({
                "receivers": {
                    "custom_receiver": {
                        "endpoint": "0.0.0.0:9090",
                    }
                },
                "exporters": {
                    "custom_exporter": {
                        "endpoint": "backend:4317",
                    }
                },
            }),
            "pipelines": ["metrics", "logs"],
        }
    ]

    # WHEN external config is added
    config_manager.add_external_configs(external_configs)

    # THEN the config contains the external components with unit name suffix
    config_yaml = config_manager.config.build()
    config_dict = yaml.safe_load(config_yaml)

    assert "receivers" in config_dict
    assert "custom_receiver/test/0" in config_dict["receivers"]
    assert config_dict["receivers"]["custom_receiver/test/0"]["endpoint"] == "0.0.0.0:9090"

    assert "exporters" in config_dict
    assert "custom_exporter/test/0" in config_dict["exporters"]
    assert config_dict["exporters"]["custom_exporter/test/0"]["endpoint"] == "backend:4317"


def test_external_config_multiple_configs(config_manager):
    """Test handling multiple external configs from different integrators."""
    # GIVEN multiple external configs
    external_configs = [
        {
            "config_yaml": yaml.safe_dump({
                "receivers": {"receiver1": {"endpoint": "0.0.0.0:8001"}}
            }),
            "pipelines": ["metrics"],
        },
        {
            "config_yaml": yaml.safe_dump({
                "receivers": {"receiver2": {"endpoint": "0.0.0.0:8002"}}
            }),
            "pipelines": ["logs"],
        },
    ]

    # WHEN both configs are added
    config_manager.add_external_configs(external_configs)

    # THEN both configs are present in the final configuration
    config_yaml = config_manager.config.build()
    config_dict = yaml.safe_load(config_yaml)

    assert "receiver1/test/0" in config_dict["receivers"]
    assert "receiver2/test/0" in config_dict["receivers"]
    assert config_dict["receivers"]["receiver1/test/0"]["endpoint"] == "0.0.0.0:8001"
    assert config_dict["receivers"]["receiver2/test/0"]["endpoint"] == "0.0.0.0:8002"


def test_no_external_config_relation(ctx, otelcol_container):
    """Test charm behavior when external-config relation is not present."""
    # GIVEN otelcol deployed without external-config relation
    state = State(relations=[], containers=otelcol_container, leader=True)

    # WHEN the charm starts
    with patch("integrations.OtelcolIntegratorRequirer") as mock_requirer_class:
        mock_requirer = MagicMock()
        mock_requirer.retrieve_external_configs.return_value = []
        mock_requirer.secret_files = {}
        mock_requirer_class.return_value = mock_requirer

        out = ctx.run(ctx.on.start(), state)

    # THEN the charm runs successfully without errors
    # The external_configs should be empty
    assert out.unit_status.name == "active"


def test_external_config_with_all_component_types(config_manager):
    """Test external config with receivers, processors, exporters, and connectors."""
    # GIVEN comprehensive external config
    external_configs = [
        {
            "config_yaml": yaml.safe_dump({
                "receivers": {
                    "test_receiver": {"endpoint": "0.0.0.0:8080"}
                },
                "processors": {
                    "test_processor": {"timeout": "30s"}
                },
                "exporters": {
                    "test_exporter": {"endpoint": "backend:4317"}
                },
                "connectors": {
                    "test_connector": {"config": "value"}
                },
            }),
            "pipelines": ["metrics", "logs", "traces"],
        }
    ]

    # WHEN external config is added
    config_manager.add_external_configs(external_configs)

    # THEN all component types are present
    config_yaml = config_manager.config.build()
    config_dict = yaml.safe_load(config_yaml)

    assert "test_receiver/test/0" in config_dict["receivers"]
    assert "test_processor/test/0" in config_dict["processors"]
    assert "test_exporter/test/0" in config_dict["exporters"]
    assert "test_connector/test/0" in config_dict["connectors"]


def test_external_config_invalid_yaml_with_error_handling(config_manager):
    """Test that invalid YAML is caught and logged with try/except."""
    # GIVEN external config with invalid YAML syntax
    external_configs = [
        {
            "config_yaml": "invalid: yaml: content: [unclosed bracket",
            "pipelines": ["metrics"],
        }
    ]

    # WHEN external config is added
    with patch("config_manager.logger") as mock_logger:
        config_manager.add_external_configs(external_configs)

        # THEN an error is logged and processing continues
        mock_logger.error.assert_called_once()
        call_args = str(mock_logger.error.call_args)
        assert "failed to parse external config YAML" in call_args
        assert "skipping" in call_args


def test_external_config_missing_config_yaml_key(config_manager):
    """Test that configs missing 'config_yaml' key are skipped with warning."""
    # GIVEN external config missing 'config_yaml' key
    external_configs = [
        {
            "pipelines": ["metrics"],
            # Missing 'config_yaml' key
        }
    ]

    # WHEN external config is added
    with patch("config_manager.logger") as mock_logger:
        config_manager.add_external_configs(external_configs)

        # THEN a warning is logged
        mock_logger.warning.assert_called_once_with(
            "external configs missing 'config_yaml' key, skipping"
        )

    # AND the config remains unchanged
    config_yaml = config_manager.config.build()
    config_dict = yaml.safe_load(config_yaml)
    # Should not have any external components added
    assert not any(key.endswith("/test/0") for key in config_dict.get("receivers", {}).keys())


def test_external_config_missing_pipelines_key(config_manager):
    """Test that configs missing 'pipelines' key are skipped with warning."""
    # GIVEN external config missing 'pipelines' key
    external_configs = [
        {
            "config_yaml": yaml.safe_dump({"receivers": {"test": {}}}),
            # Missing 'pipelines' key
        }
    ]

    # WHEN external config is added
    with patch("config_manager.logger") as mock_logger:
        config_manager.add_external_configs(external_configs)

        # THEN a warning is logged
        mock_logger.warning.assert_called_once_with(
            "external configs missing 'pipelines' key, skipping"
        )

    # AND the config remains unchanged
    config_yaml = config_manager.config.build()
    config_dict = yaml.safe_load(config_yaml)
    # Should not have any external components added
    assert not any(key.endswith("/test/0") for key in config_dict.get("receivers", {}).keys())


def test_external_config_invalid_component_type(config_manager):
    """Test that invalid component types are skipped with warning."""
    # GIVEN external config with an invalid component type
    external_configs = [
        {
            "config_yaml": yaml.safe_dump({
                "invalid_component_type": {
                    "some_component": {"config": "value"}
                },
                "receivers": {
                    "valid_receiver": {"endpoint": "0.0.0.0:8080"}
                },
            }),
            "pipelines": ["metrics"],
        }
    ]

    # WHEN external config is added
    with patch("config_manager.logger") as mock_logger:
        config_manager.add_external_configs(external_configs)

        # THEN a warning is logged for the invalid component type
        mock_logger.warning.assert_called()
        call_args_str = str(mock_logger.warning.call_args_list)
        assert "wrong component type" in call_args_str
        assert "invalid_component_type" in call_args_str

    # AND only the valid receiver is added
    config_yaml = config_manager.config.build()
    config_dict = yaml.safe_load(config_yaml)
    assert "valid_receiver/test/0" in config_dict["receivers"]
    # Invalid component type should not be in the config
    assert "invalid_component_type" not in config_dict

