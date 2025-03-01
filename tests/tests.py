import json
import os
from base64 import b64encode
from unittest import mock

import docker
import pytest
import requests

# We need to mock the docker client before importing the script
# Create a mock for docker.DockerClient
mock_docker_client = mock.MagicMock()
docker.DockerClient = mock.MagicMock(return_value=mock_docker_client)

# Now import the module after mocking Docker
import traefik_adguard_auto_rewrites as script


@pytest.fixture(autouse=True)
def prevent_actual_docker_usage():
    """Fixture to prevent actual Docker API calls"""
    with mock.patch("docker.DockerClient", return_value=mock_docker_client):
        yield


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


def test_get_auth_header():
    """Test the get_auth_header function"""
    header = script.get_auth_header()

    credentials = "test_user:test_pass"
    encoded = b64encode(credentials.encode()).decode()
    expected = {"Authorization": f"Basic {encoded}"}

    assert header == expected


def test_get_auth_header_missing_credentials():
    """Test get_auth_header with missing credentials"""
    with mock.patch.dict(os.environ, {"ADGUARD_USERNAME": "", "ADGUARD_PASSWORD": ""}):
        script.adguard_username = ""
        script.adguard_password = ""

        with pytest.raises(SystemExit):
            script.get_auth_header()


def test_ip_test_valid():
    """Test ip_test function with valid IP"""
    is_ip, ip = script.ip_test("192.168.1.1")
    assert is_ip is True
    assert ip == "192.168.1.1"


def test_ip_test_invalid():
    """Test ip_test function with invalid IP"""
    is_ip, ip = script.ip_test("not-an-ip")
    assert is_ip is False
    assert ip == "not-an-ip"


def test_flush_list(temp_state_file):
    """Test flush_list function"""
    script.global_list = {("example.com", "192.168.1.1"), ("test.com", "192.168.1.2")}
    script.flush_list()

    assert temp_state_file.exists()
    content = json.loads(temp_state_file.read())
    assert {tuple(x) for x in content} == script.global_list


def test_read_state_existing_file(temp_state_file):
    """Test read_state function with existing file"""
    test_data = [["example.com", "192.168.1.1"], ["test.com", "192.168.1.2"]]
    temp_state_file.write(json.dumps(test_data))

    script.global_list = set()
    script.read_state()

    expected = {("example.com", "192.168.1.1"), ("test.com", "192.168.1.2")}
    assert script.global_list == expected


def test_read_state_no_file():
    """Test read_state function with no file"""
    with mock.patch("os.path.exists", return_value=False):
        script.global_list = set()
        script.read_state()
        assert script.global_list == set()


def test_list_existing(mock_requests):
    """Test list_existing function"""
    mock_get, _ = mock_requests
    mock_response = mock.Mock()
    mock_response.json.return_value = [
        {"domain": "example.com", "answer": "192.168.1.1"},
        {"domain": "test.com", "answer": "192.168.1.2"},
    ]
    mock_response.raise_for_status.return_value = None
    mock_get.return_value = mock_response

    result = script.list_existing()
    expected = {("example.com", "192.168.1.1"), ("test.com", "192.168.1.2")}

    assert result == expected
    mock_get.assert_called_once()


def test_list_existing_error(mock_requests):
    """Test list_existing function with an error"""
    mock_get, _ = mock_requests
    mock_get.side_effect = requests.RequestException("API Error")

    result = script.list_existing()
    assert result == set()


def test_add_object_new(mock_requests):
    """Test add_object function with a new record"""
    _, mock_post = mock_requests
    mock_response = mock.Mock()
    mock_response.raise_for_status.return_value = None
    mock_post.return_value = mock_response

    existing = {("other.com", "192.168.1.3")}
    script.global_list = set()

    script.add_object(("example.com", "192.168.1.1"), existing)

    mock_post.assert_called_once()
    assert ("example.com", "192.168.1.1") in script.global_list


def test_add_object_existing(mock_requests):
    """Test add_object function with an existing record"""
    _, mock_post = mock_requests

    existing = {("example.com", "192.168.1.1")}
    script.global_list = set()

    script.add_object(("example.com", "192.168.1.1"), existing)

    mock_post.assert_not_called()
    assert ("example.com", "192.168.1.1") in script.global_list


def test_add_object_error(mock_requests):
    """Test add_object function with an error"""
    _, mock_post = mock_requests
    mock_post.side_effect = requests.RequestException("API Error")

    existing = set()
    script.global_list = set()

    script.add_object(("example.com", "192.168.1.1"), existing)

    mock_post.assert_called_once()
    assert len(script.global_list) == 0


def test_remove_object_existing(mock_requests):
    """Test remove_object function with an existing record"""
    _, mock_post = mock_requests
    mock_response = mock.Mock()
    mock_response.raise_for_status.return_value = None
    mock_post.return_value = mock_response

    existing = {("example.com", "192.168.1.1")}
    script.global_list = {("example.com", "192.168.1.1")}

    script.remove_object(("example.com", "192.168.1.1"), existing)

    mock_post.assert_called_once()
    assert len(script.global_list) == 0


def test_remove_object_not_existing(mock_requests):
    """Test remove_object function with a non-existing record"""
    _, mock_post = mock_requests

    existing = set()
    script.global_list = {("example.com", "192.168.1.1")}

    script.remove_object(("example.com", "192.168.1.1"), existing)

    mock_post.assert_not_called()
    assert len(script.global_list) == 0


def test_remove_object_error(mock_requests):
    """Test remove_object function with an error"""
    _, mock_post = mock_requests
    mock_post.side_effect = requests.RequestException("API Error")

    existing = {("example.com", "192.168.1.1")}
    script.global_list = {("example.com", "192.168.1.1")}

    script.remove_object(("example.com", "192.168.1.1"), existing)

    mock_post.assert_called_once()
    assert ("example.com", "192.168.1.1") in script.global_list


def test_handle_list():
    """Test handle_list function"""
    with mock.patch("traefik_adguard_auto_rewrites.add_object") as mock_add, mock.patch(
        "traefik_adguard_auto_rewrites.remove_object"
    ) as mock_remove, mock.patch(
        "traefik_adguard_auto_rewrites.print_state"
    ), mock.patch(
        "traefik_adguard_auto_rewrites.flush_list"
    ):
        # Setup
        script.global_list = {
            ("existing.com", "192.168.1.1"),
            ("to_remove.com", "192.168.1.2"),
        }

        new_global_list = {
            ("existing.com", "192.168.1.1"),
            ("to_add.com", "192.168.1.3"),
        }

        existing = {("existing.com", "192.168.1.1")}

        # Test
        script.handle_list(new_global_list, existing)

        # Assertions
        mock_add.assert_called_with(("to_add.com", "192.168.1.3"), existing)
        mock_remove.assert_called_with(("to_remove.com", "192.168.1.2"), existing)


def test_process_container_labels_with_host(sample_container):
    """Test process_container_labels function with Host rules"""
    result = script.process_container_labels(sample_container)
    assert result == {("example.com", "192.168.1.100")}


def test_process_container_labels_with_multiple_hosts():
    """Test process_container_labels function with multiple hosts"""
    container = mock.Mock()
    container.id = "test_container_id"
    container.labels = {
        "traefik.http.routers.app.rule": "Host(`example.com`, `test.com`)",
        "adguard.dns.target.override": "192.168.1.100",
    }

    result = script.process_container_labels(container)
    assert result == {("example.com", "192.168.1.100"), ("test.com", "192.168.1.100")}


def test_process_container_labels_with_default_ip():
    """Test process_container_labels using default DNS target"""
    container = mock.Mock()
    container.id = "test_container_id"
    container.labels = {"traefik.http.routers.app.rule": "Host(`example.com`)"}

    result = script.process_container_labels(container)
    assert result == {("example.com", "192.168.1.100")}


def test_process_container_labels_with_complex_rule():
    """Test process_container_labels with complex Traefik rules"""
    container = mock.Mock()
    container.id = "test_container_id"
    container.labels = {
        "traefik.http.routers.app.rule": "Host(`example.com`) || Path(`/test`) || Host(`another.com`)",
        "adguard.dns.target.override": "192.168.1.100",
    }

    result = script.process_container_labels(container)
    assert result == {
        ("example.com", "192.168.1.100"),
        ("another.com", "192.168.1.100"),
    }


def test_initial_sync():
    """Test initial_sync function"""
    # Setup mock containers
    container1 = mock.Mock()
    container1.id = "container1"
    container1.labels = {"traefik.http.routers.app1.rule": "Host(`example.com`)"}

    container2 = mock.Mock()
    container2.id = "container2"
    container2.labels = {"traefik.http.routers.app2.rule": "Host(`test.com`)"}

    # Set up mock container list
    mock_docker_client.containers.list.return_value = [container1, container2]

    # Setup mock list_existing
    with mock.patch(
        "traefik_adguard_auto_rewrites.list_existing", return_value=set()
    ) as mock_list_existing, mock.patch(
        "traefik_adguard_auto_rewrites.handle_list"
    ) as mock_handle_list:
        # Clear state
        script.global_list = set()
        script.container_records = {}

        # Run the test
        script.initial_sync()

        # Check correct container records
        assert "container1" in script.container_records
        assert "container2" in script.container_records
        assert script.container_records["container1"] == {
            ("example.com", "192.168.1.100")
        }
        assert script.container_records["container2"] == {("test.com", "192.168.1.100")}

        # Check handle_list was called with correct arguments
        expected_records = {
            ("example.com", "192.168.1.100"),
            ("test.com", "192.168.1.100"),
        }
        mock_list_existing.assert_called_once()
        mock_handle_list.assert_called_once()
        args = mock_handle_list.call_args[0]
        assert args[0] == expected_records
