import os
import yaml

CONFIG_FILE = "stats.yaml"

def load_config():
    """Reads the stats.yaml file if it exists; otherwise, returns an empty dictionary."""
    if os.path.exists(CONFIG_FILE):
        with open(CONFIG_FILE, "r") as file:
            return yaml.safe_load(file) or {}
    return {}

def save_config(args_dict):
    """Overwrites stats.yaml with the current configuration."""
    current_config = load_config()
    
    # Update only the values explicitly provided by the user via CLI
    for key, value in args_dict.items():
        if value is not None:
            current_config[key] = value

    with open(CONFIG_FILE, "w") as file:
        yaml.dump(current_config, file, default_flow_style=False)
    
    return current_config