import os
import yaml

CONFIG_FILE = "stats.yaml"

def load_config():
    # Read stats.yaml if it exists
    if os.path.exists(CONFIG_FILE):
        with open(CONFIG_FILE, "r") as file:
            return yaml.safe_load(file) or {}
    return {}

def save_config(args_dict):
    # Update stats.yaml with new CLI args
    current_config = load_config()
    
    for key, value in args_dict.items():
        if value is not None:
            current_config[key] = value

    with open(CONFIG_FILE, "w") as file:
        yaml.dump(current_config, file, default_flow_style=False)
    
    return current_config