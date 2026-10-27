from file import standardize_file_path_and_name
from network import standardize_network_socket
from process import standardize_process_commandline
from registry import standardize_registry_keys


STANDARDIZATION_FUNCTIONS = {
    "registry": standardize_registry_keys,
    "network": standardize_network_socket,
    "file": standardize_file_path_and_name,
    "process": standardize_process_commandline,
}


def standardize(input_string, type, mapping_collector=None, process_profile="default"):
    """
    Supported artifact types:
    - registry
    - network
    - file
    - process

    mapping_collector:
    - optional list for collecting (raw, standardized) pairs
    """

    if type not in STANDARDIZATION_FUNCTIONS:
        raise ValueError(
            f"Unsupported standardization type: {type}. Expected one of registry, network, file, process."
        )

    fn = STANDARDIZATION_FUNCTIONS[type]
    if type == "process":
        return fn(input_string, mapping_collector=mapping_collector, profile=process_profile)
    return fn(input_string, mapping_collector=mapping_collector)
