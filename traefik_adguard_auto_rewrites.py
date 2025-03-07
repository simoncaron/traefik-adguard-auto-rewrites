import json
import logging
import os
import sys
import threading
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
removal_interval = os.getenv("REWRITE_RULE_REMOVAL_DELAY", 30)
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

container_records = {}
pending_removals = {}
container_domains = {}
removal_scheduled = set()


def get_auth_header() -> dict[str, str]:
    """Generate Basic Auth header for AdGuard Home API"""
    if not adguard_username or not adguard_password:
        logger.error("AdGuard Home credentials not set")
        sys.exit(1)
    credentials = f"{adguard_username}:{adguard_password}"
    encoded = b64encode(credentials.encode()).decode()
    return {"Authorization": f"Basic {encoded}"}


def save_state() -> None:
    """Save current state to file"""
    json_object = json.dumps(list(global_list), indent=2)
    with open(state_file_path, "w") as outfile:
        outfile.write(json_object)


def load_state() -> None:
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


def list_existing_rewrite_rules() -> set:
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


def add_rewrite_rule(obj: tuple[str, str], existing: set[tuple[str, str]]) -> None:
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


def remove_rewrite_rule(obj: tuple[str, str], existing: set[tuple[str, str]]) -> None:
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


def manage_rewrite_rules(
    new_global_list: set[tuple[str, str]], existing: set[tuple[str, str]]
) -> None:
    """Handle changes in DNS rewrites"""
    to_add = {x for x in new_global_list if x not in global_list}
    to_remove = {x for x in global_list if x not in new_global_list}
    to_sync = {x for x in global_list if x not in existing}

    if len(to_add) > 0:
        logger.debug(f"Rewrite rule to add: {to_add}")
        for add in to_add:
            add_rewrite_rule(add, existing)

    if len(to_remove) > 0:
        logger.debug(f"Rewrite rule to remove: {to_remove}")
        for remove in to_remove:
            remove_rewrite_rule(remove, existing)

    if len(to_sync) > 0:
        logger.debug(f"Rewrite rule to sync: {to_sync}")
        for sync in to_sync - to_add - to_remove:
            add_rewrite_rule(sync, existing)

    print_state()
    save_state()


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
    global container_records, container_domains

    logger.info("Performing initial synchronization...")
    containers = client.containers.list()
    existing = list_existing_rewrite_rules()

    for container in containers:
        records = process_container_labels(container)
        if records:
            container_records[container.id] = records
            # Track domains for each container
            domains = {domain for domain, _ in records}
            container_domains[container.id] = domains

    # Handle state file entries that might not have an associated container
    load_state()

    # Create a set of all domains from container records
    active_domains = set()
    for records in container_records.values():
        active_domains.update(domain for domain, _ in records)

    # Combine all records from all containers with state
    new_global_list = set()
    for records in container_records.values():
        new_global_list.update(records)

    # Add state entries to container_domains with special ID
    state_domains = {domain for domain, _ in global_list} - active_domains
    if state_domains:
        logger.info(
            f"Found {len(state_domains)} domains in state file not associated with active containers"
        )
        container_domains["__state_file__"] = state_domains
        # Keep these entries in the global list
        new_global_list.update(global_list)

    manage_rewrite_rules(new_global_list, existing)
    logger.info("Initial synchronization completed")


def handle_container_event(container_event: Any, removal_delay: int = 30) -> None:
    """Handle a Docker container event"""
    global container_records, pending_removals, container_domains, removal_scheduled

    try:
        container_id = container_event["id"]
        action = container_event["Action"]
        logger.debug(f"Container event: {action} for {container_id}")

        if action == "start":
            # Container started - process its labels for DNS records
            container = client.containers.get(container_id)
            records = process_container_labels(container)

            # Clear any scheduled removal flag for this container
            if container_id in removal_scheduled:
                removal_scheduled.remove(container_id)

            if records:
                # Track domains for this container
                domains = {domain for domain, _ in records}
                container_domains[container_id] = domains

                # Check if any of these domains were pending removal
                for domain, _ in records:
                    if domain in pending_removals:
                        logger.info(
                            f"Domain {domain} was pending removal but is now used by a new container"
                        )
                        pending_removals.pop(domain, None)

                # Update container records and sync
                container_records[container_id] = records
                sync_rewrite_rules()

        elif action in ["die", "stop", "kill"]:
            # Only process if container is in our records and not already scheduled for removal
            if (
                container_id in container_records
                and container_id not in removal_scheduled
            ):
                # Mark container as having removal scheduled
                removal_scheduled.add(container_id)

                # Get domains used by this container
                domains = container_domains.get(container_id, set())

                def delayed_domain_removal():
                    logger.debug(
                        f"Checking for domains to remove after delay for container {container_id}"
                    )
                    domains_to_remove = []

                    # Check each domain to see if it's still pending removal
                    for domain in domains:
                        if (
                            domain in pending_removals
                            and pending_removals[domain] == container_id
                        ):
                            domains_to_remove.append(domain)
                            pending_removals.pop(domain, None)

                    if domains_to_remove:
                        logger.info(
                            f"Removing domains after delay: {domains_to_remove}"
                        )
                        # Remove container from records and sync
                        if container_id in container_records:
                            del container_records[container_id]
                        if container_id in container_domains:
                            del container_domains[container_id]
                        sync_rewrite_rules()

                    # Remove from scheduled set when done
                    removal_scheduled.discard(container_id)

                # Mark domains for pending removal
                for domain in domains:
                    pending_removals[domain] = container_id

                # Schedule removal after delay
                logger.info(
                    f"Container {container_id} {action}. Scheduling domain removal in {removal_delay} seconds"
                )
                timer = threading.Timer(removal_delay, delayed_domain_removal)
                timer.daemon = True
                timer.start()
            else:
                logger.debug(
                    f"Ignoring {action} event for container {container_id}, removal already scheduled"
                )

    except Exception as e:
        logger.error(f"Error handling container event: {e}")


def sync_rewrite_rules() -> None:
    """Synchronize current container records with AdGuard Home"""
    # Combine all records from all containers
    new_global_list = set()
    for records in container_records.values():
        new_global_list.update(records)

    existing = list_existing_rewrite_rules()
    manage_rewrite_rules(new_global_list, existing)


if __name__ == "__main__":
    if not adguard_username or not adguard_password:
        logger.error(
            "AdGuard Home credentials not set. Set ADGUARD_USERNAME and ADGUARD_PASSWORD environment variables."
        )
        sys.exit(1)

    initial_sync()

    # Listen for Docker events
    logger.info("Listening for Docker container events...")
    for event in client.events(decode=True, filters={"type": "container"}):
        handle_container_event(event)
