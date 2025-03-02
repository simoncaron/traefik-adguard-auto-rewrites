import json
import os
from base64 import b64encode
from unittest import mock

import pytest
import requests

# IMPORTANT: Mock Docker before importing docker module
docker_patch = mock.patch("docker.DockerClient")
mock_docker = docker_patch.start()

# Now it's safe to import docker
import docker

# And now import the script
import traefik_adguard_auto_rewrites as script

# Fixtures


# Expose the mock_docker_client as a fixture
@pytest.fixture(scope="session")
def mock_docker_client():
    """Provide access to the Docker client mock"""
    return mock_docker.return_value


@pytest.fixture(autouse=True)
def prevent_actual_docker_usage():
    """Fixture to prevent actual Docker API calls"""
    # The mock is already started, just yield
    yield
    # Clean up at the end of all tests
    docker_patch.stop()


@pytest.fixture
def mock_requests():
    """Mock requests library fixture"""
    with mock.patch("requests.get") as mock_get, mock.patch(
        "requests.post"
    ) as mock_post:
        yield mock_get, mock_post


@pytest.fixture
def temp_state_file(tmpdir):
    """Create a temporary state file for testing"""
    state_file = tmpdir.join("test_state.json")
    original_path = script.state_file_path
    script.state_file_path = str(state_file)
    yield state_file
    script.state_file_path = original_path


@pytest.fixture
def sample_container():
    """Create a sample container mock"""
    container = mock.Mock()
    container.id = "test_container_id"
    container.labels = {
        "traefik.http.routers.app.rule": "Host(`example.com`)",
        "adguard.dns.target.override": "192.168.1.100",
    }
    return container


@pytest.fixture(autouse=True)
def setup_environment():
    """Set up environment variables for testing"""
    with mock.patch.dict(
        os.environ,
        {
            "ADGUARD_USERNAME": "test_user",
            "ADGUARD_PASSWORD": "test_pass",
            "DEFAULT_DNS_RECORD_TARGET": "192.168.1.100",
            "ADGUARD_API_URL": "http://test-adguard:3000/control",
        },
    ):
        # Update script variables from environment
        script.adguard_username = os.environ["ADGUARD_USERNAME"]
        script.adguard_password = os.environ["ADGUARD_PASSWORD"]
        script.default_dns_record_target = os.environ["DEFAULT_DNS_RECORD_TARGET"]
        script.adguard_api_url = os.environ["ADGUARD_API_URL"]
        yield
