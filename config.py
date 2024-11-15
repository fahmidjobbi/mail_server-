import json

config_path = "config.json"


def get_settings():
    with open(config_path, 'r') as config_file:
        config_global = json.load(config_file)
        return config_global['settings'], config_global['config']
