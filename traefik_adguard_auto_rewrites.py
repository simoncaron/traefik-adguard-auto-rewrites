import json
import logging
import os
import socket
import sys
from base64 import b64encode
from typing import Any

import docker
import requests
from docker.models.containers import Container

# Environment variables
docker_socket_url = os.getenv("DOCKER_HOST", "unix://var/run/docker.sock")
default_dns_record_target = os.getenv("DEFAULT_DNS_RECORD_TARGET", "")
adguard_username = os.getenv("ADGUARD_USERNAME", "")
adguard_password = os.getenv("ADGUARD_PASSWORD", "")
adguard_api_url = os.getenv("ADGUARD_API_URL", "http://adguard:3000/control")
state_file_path = os.getenv("STATE_FILE", "/state/adguard.state")

# Initialize Docker client
client = docker.DockerClient(base_url=docker_socket_url)

# Configure logging
logging_level = logging.getLevelName(os.getenv("LOGGING_LEVEL", "INFO"))
logging.basicConfig(
    level=logging_level,
    format="%(asctime)s [%(levelname)s] %(message)s",
    handlers=[logging.StreamHandler()],
)
logger = logging.getLogger(__name__)

# Global state
global_list: set = set()

# Container records mapping (container_id -> set of records)
container_records = {}


def get_auth_header() -> dict[str, str]:
    """Generate Basic Auth header for AdGuard Home API"""
    if not adguard_username or not adguard_password:
        logger.error("AdGuard Home credentials not set")
        sys.exit(1)
    credentials = f"{adguard_username}:{adguard_password}"
    encoded = b64encode(credentials.encode()).decode()
    return {"Authorization": f"Basic {encoded}"}


def ip_test(ip: str) -> tuple[bool, str]:
    """Test if a string is a valid IP address"""
    is_ip = False
    try:
        socket.inet_aton(ip)
        is_ip = True
    except Exception as ex:
        template = "An exception of type {0} occurred. Arguments:\n{1!r}"
        message = template.format(type(ex).__name__, ex.args)
        logger.debug(message)
    return is_ip, ip


def flush_list() -> None:
    """Save current state to file"""
    json_object = json.dumps(list(global_list), indent=2)
    with open(state_file_path, "w") as outfile:
        outfile.write(json_object)


def read_state() -> None:
    """Read state from file"""
    file_exists = os.path.exists(state_file_path)
    if file_exists:
        logger.info("Loading existing state...")
        with open(state_file_path, "r") as openfile:
            read_list = json.load(openfile)
            for obj in read_list:
                logger.info("From file (%s): %s" % (type(obj), obj))
                global_list.add(tuple(obj))
    else:
        logger.info("Loading skipped, no db found.")


def print_state() -> None:
    """Print current state for debugging"""
    logger.debug("State")
    logger.debug("-----------")
    for obj in global_list:
        logger.debug(obj)
    logger.debug("-----------")


def list_existing() -> set:
    """Fetch current DNS rewrites from AdGuard Home"""
    try:
        response = requests.get(
            f"{adguard_api_url}/rewrite/list", headers=get_auth_header()
        )
        response.raise_for_status()

        rewrites = response.json()
        existing = set()
        for rewrite in rewrites:
            existing.add((rewrite["domain"], rewrite["answer"]))

        logger.debug(f"Existing DNS rewrites: {existing}")
        return existing
    except Exception as e:
        logger.error(f"Failed to fetch DNS rewrites: {str(e)}")
        return set()


def add_object(obj: tuple[str, str], existing: set[tuple[str, str]]) -> None:
    """Add a DNS rewrite to AdGuard Home"""
    domain, target = obj
    logger.info(f"Adding: {domain} -> {target}")

    if obj in existing:
        logger.debug("This record already exists, adding to state.")
        global_list.add(obj)
        return

    try:
        response = requests.post(
            f"{adguard_api_url}/rewrite/add",
            headers=get_auth_header(),
            json={"domain": domain, "answer": target},
        )
        response.raise_for_status()
        global_list.add(obj)
        logger.info(f"Added to global list: {obj}")
    except Exception as e:
        logger.error(f"Failed to add DNS rewrite: {str(e)}")


def remove_object(obj: tuple[str, str], existing: set[tuple[str, str]]) -> None:
    """Remove a DNS rewrite from AdGuard Home"""
    domain, target = obj
    logger.info(f"Removing: {domain} -> {target}")

    if obj not in existing:
        logger.debug("This record doesn't exist, removing from state.")
        global_list.remove(obj)
        return

    try:
        response = requests.post(
            f"{adguard_api_url}/rewrite/delete",
            headers=get_auth_header(),
            json={"domain": domain, "answer": target},
        )
        response.raise_for_status()
        global_list.remove(obj)
        logger.info(f"Removed from global list: {obj}")
    except Exception as e:
        logger.error(f"Failed to remove DNS rewrite: {str(e)}")


def handle_list(
    new_global_list: set[tuple[str, str]], existing: set[tuple[str, str]]
) -> None:
    """Handle changes in DNS rewrites"""
    to_add = {x for x in new_global_list if x not in global_list}
    to_remove = {x for x in global_list if x not in new_global_list}
    to_sync = {x for x in global_list if x not in existing}

    if len(to_add) > 0:
        logger.debug(f"Records to add: {to_add}")
        for add in to_add:
            add_object(add, existing)

    if len(to_remove) > 0:
        logger.debug(f"Records to remove: {to_remove}")
        for remove in to_remove:
            remove_object(remove, existing)

    if len(to_sync) > 0:
        logger.debug(f"Records to sync: {to_sync}")
        for sync in to_sync - to_add - to_remove:
            add_object(sync, existing)

    print_state()
    flush_list()


def process_container_labels(container: Container) -> set[tuple[str, str]]:
    """Process a container's labels and extract DNS records"""
    records = set()
    host_ip = container.labels.get(
        "adguard.dns.target.override", default_dns_record_target
    )

    for key, value in container.labels.items():
        if (
            key.startswith("traefik.http.routers.")
            or key.startswith("traefik.https.routers.")
        ) and key.endswith(".rule"):
            host_directives = value.split("||")
            for directive in host_directives:
                if "Host(" in directive:
                    directive = directive.split("Host(")[-1].rstrip(")'\" ")
                    domains = [
                        domain.strip("` ,")
                        for domain in directive.split(",")
                        if domain.strip()
                    ]
                    for domain in domains:
                        records.add((domain, host_ip))

    return records


def initial_sync() -> None:
    """Perform initial synchronization of all running containers"""
    global container_records

    logger.info("Performing initial synchronization...")
    containers = client.containers.list()
    existing = list_existing()

    for container in containers:
        records = process_container_labels(container)
        if records:
            container_records[container.id] = records

    # Combine all records from all containers
    new_global_list = set()
    for records in container_records.values():
        new_global_list.update(records)

    handle_list(new_global_list, existing)
    logger.info("Initial synchronization completed")


def handle_container_event(event: Any) -> None:
    """Handle a Docker container event"""
    global container_records

    try:
        container_id = event["id"]
        action = event["Action"]
        logger.debug(f"Container event: {action} for {container_id}")

        if action == "start":
            # Container started - add its records
            container = client.containers.get(container_id)
            records = process_container_labels(container)
            if records:
                container_records[container_id] = records
                sync_records()

        elif action in ["die", "stop", "kill"]:
            # Container stopped - remove its records
            if container_id in container_records:
                del container_records[container_id]
                sync_records()

        elif action == "update":
            # Container updated - refresh its records
            container = client.containers.get(container_id)
            records = process_container_labels(container)

            # Check if records changed
            old_records = container_records.get(container_id, set())
            if records != old_records:
                if records:
                    container_records[container_id] = records
                else:
                    container_records.pop(container_id, None)
                sync_records()

    except Exception as e:
        logger.error(f"Error handling container event: {e}")


def sync_records() -> None:
    """Synchronize current container records with AdGuard Home"""
    # Combine all records from all containers
    new_global_list = set()
    for records in container_records.values():
        new_global_list.update(records)

    existing = list_existing()
    handle_list(new_global_list, existing)


if __name__ == "__main__":
    if not adguard_username or not adguard_password:
        logger.error(
            "AdGuard Home credentials not set. Set ADGUARD_USERNAME and ADGUARD_PASSWORD environment variables."
        )
        sys.exit(1)

    read_state()
    initial_sync()

    # Listen for Docker events
    logger.info("Listening for Docker container events...")
    for event in client.events(decode=True, filters={"type": "container"}):
        handle_container_event(event)
