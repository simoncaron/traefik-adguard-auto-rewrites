import json
import os
import socket
from base64 import b64encode
from unittest import mock

import docker
import pytest
import requests

# Now import the module after mocking Docker
import traefik_adguard_auto_rewrites as script


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


def test_flush_list(temp_state_file):
    """Test flush_list function"""
    script.global_list = {("example.com", "192.168.1.1"), ("test.com", "192.168.1.2")}
    script.save_state()

    assert temp_state_file.exists()
    content = json.loads(temp_state_file.read())
    assert set(tuple(x) for x in content) == script.global_list


def test_read_state_existing_file(temp_state_file):
    """Test read_state function with existing file"""
    test_data = [["example.com", "192.168.1.1"], ["test.com", "192.168.1.2"]]
    temp_state_file.write(json.dumps(test_data))

    script.global_list = set()
    script.load_state()

    expected = {("example.com", "192.168.1.1"), ("test.com", "192.168.1.2")}
    assert script.global_list == expected


def test_read_state_no_file():
    """Test read_state function with no file"""
    with mock.patch("os.path.exists", return_value=False):
        script.global_list = set()
        script.load_state()
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

    result = script.list_existing_rewrite_rules()
    expected = {("example.com", "192.168.1.1"), ("test.com", "192.168.1.2")}

    assert result == expected
    mock_get.assert_called_once()


def test_list_existing_error(mock_requests):
    """Test list_existing function with an error"""
    mock_get, _ = mock_requests
    mock_get.side_effect = requests.RequestException("API Error")

    result = script.list_existing_rewrite_rules()
    assert result == set()


def test_add_object_new(mock_requests):
    """Test add_object function with a new record"""
    _, mock_post = mock_requests
    mock_response = mock.Mock()
    mock_response.raise_for_status.return_value = None
    mock_post.return_value = mock_response

    existing = {("other.com", "192.168.1.3")}
    script.global_list = set()

    script.add_rewrite_rule(("example.com", "192.168.1.1"), existing)

    mock_post.assert_called_once()
    assert ("example.com", "192.168.1.1") in script.global_list


def test_add_object_existing(mock_requests):
    """Test add_object function with an existing record"""
    _, mock_post = mock_requests

    existing = {("example.com", "192.168.1.1")}
    script.global_list = set()

    script.add_rewrite_rule(("example.com", "192.168.1.1"), existing)

    mock_post.assert_not_called()
    assert ("example.com", "192.168.1.1") in script.global_list


def test_add_object_error(mock_requests):
    """Test add_object function with an error"""
    _, mock_post = mock_requests
    mock_post.side_effect = requests.RequestException("API Error")

    existing = set()
    script.global_list = set()

    script.add_rewrite_rule(("example.com", "192.168.1.1"), existing)

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

    script.remove_rewrite_rule(("example.com", "192.168.1.1"), existing)

    mock_post.assert_called_once()
    assert len(script.global_list) == 0


def test_remove_object_not_existing(mock_requests):
    """Test remove_object function with a non-existing record"""
    _, mock_post = mock_requests

    existing = set()
    script.global_list = {("example.com", "192.168.1.1")}

    script.remove_rewrite_rule(("example.com", "192.168.1.1"), existing)

    mock_post.assert_not_called()
    assert len(script.global_list) == 0


def test_remove_object_error(mock_requests):
    """Test remove_object function with an error"""
    _, mock_post = mock_requests
    mock_post.side_effect = requests.RequestException("API Error")

    existing = {("example.com", "192.168.1.1")}
    script.global_list = {("example.com", "192.168.1.1")}

    script.remove_rewrite_rule(("example.com", "192.168.1.1"), existing)

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
        script.manage_rewrite_rules(new_global_list, existing)

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


def test_initial_sync(mock_docker_client):
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


def test_handle_container_event_start(mock_docker_client):
    """Test handle_container_event for container start event"""
    # Setup mock container
    container = mock.Mock()
    container.id = "test_container"
    container.labels = {"traefik.http.routers.app.rule": "Host(`example.com`)"}

    # Setup container get return
    mock_docker_client.containers.get.return_value = container

    # Clear state
    script.container_records = {}

    # Create event
    event = {"id": "test_container", "Action": "start"}

    # Mock sync_records function
    with mock.patch("traefik_adguard_auto_rewrites.sync_records") as mock_sync:
        script.handle_container_event(event)

        # Check container records updated
        assert "test_container" in script.container_records
        assert script.container_records["test_container"] == {
            ("example.com", "192.168.1.100")
        }

        # Verify sync_records was called
        mock_sync.assert_called_once()


def test_handle_container_event_stop():
    """Test handle_container_event for container stop event"""
    # Setup initial container records
    script.container_records = {"test_container": {("example.com", "192.168.1.100")}}

    # Create stop event
    event = {"id": "test_container", "Action": "stop"}

    # Mock sync_records function
    with mock.patch("traefik_adguard_auto_rewrites.sync_records") as mock_sync:
        script.handle_container_event(event)

        # Check container records removed
        assert "test_container" not in script.container_records

        # Verify sync_records was called
        mock_sync.assert_called_once()


def test_handle_container_event_update(mock_docker_client):
    """Test handle_container_event for container update event"""
    # Setup initial container records
    script.container_records = {
        "test_container": {("old.example.com", "192.168.1.100")}
    }

    # Setup mock updated container
    container = mock.Mock()
    container.id = "test_container"
    container.labels = {"traefik.http.routers.app.rule": "Host(`new.example.com`)"}
    mock_docker_client.containers.get.return_value = container

    # Create update event
    event = {"id": "test_container", "Action": "update"}

    # Mock sync_records function
    with mock.patch("traefik_adguard_auto_rewrites.sync_records") as mock_sync:
        script.handle_container_event(event)

        # Check container records updated
        assert script.container_records["test_container"] == {
            ("new.example.com", "192.168.1.100")
        }

        # Verify sync_records was called
        mock_sync.assert_called_once()


def test_handle_container_event_exception(mock_docker_client):
    """Test exception handling in handle_container_event"""
    # Force an exception when getting container
    mock_docker_client.containers.get.side_effect = docker.errors.NotFound(
        "Container not found"
    )

    # Create event
    event = {"id": "test_container", "Action": "start"}

    # The function should not raise an exception
    script.handle_container_event(event)

    # Reset side effect for other tests
    mock_docker_client.containers.get.side_effect = None


def test_process_container_no_host_labels():
    """Test process_container_labels with no Host rules"""
    container = mock.Mock()
    container.id = "test_container_id"
    container.labels = {
        "traefik.http.routers.app.rule": "Path(`/test`)",
        "other.label": "value",
    }

    result = script.process_container_labels(container)
    assert result == set()


def test_sync_records():
    """Test sync_records function"""
    # Setup container records
    script.container_records = {
        "container1": {("example.com", "192.168.1.100")},
        "container2": {("test.com", "192.168.1.100")},
    }

    # Mock list_existing and handle_list
    with mock.patch(
        "traefik_adguard_auto_rewrites.list_existing", return_value=set()
    ) as mock_list_existing, mock.patch(
        "traefik_adguard_auto_rewrites.handle_list"
    ) as mock_handle_list:
        script.sync_rewrite_rules()

        # Check handle_list was called with correct arguments
        expected_records = {
            ("example.com", "192.168.1.100"),
            ("test.com", "192.168.1.100"),
        }
        mock_list_existing.assert_called_once()
        mock_handle_list.assert_called_once()
        args = mock_handle_list.call_args[0]
        assert args[0] == expected_records
