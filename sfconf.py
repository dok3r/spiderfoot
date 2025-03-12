#!/usr/bin/env python

import glob
import json
import os
import argparse
from spiderfoot import SpiderFootDb

def load_configs(config_dir):
    configs = {}
    for conf_file in glob.glob(os.path.join(config_dir, "*.json")):
        print(f"Loading {conf_file}")
        try:
            with open(conf_file, "r") as f:
                configs.update(json.load(f))
        except (json.JSONDecodeError, FileNotFoundError, PermissionError) as e:
            print(f"Warning: Failed to load {conf_file}: {e}")
    return configs

def load_json(json_source):
    if not json_source:
        return {}
    try:
        return json.loads(json_source)
    except json.JSONDecodeError as e:
        print(f"Warning: Failed to load JSON: {e}")
    return {}

def load_api_keys(api_key_file):
    api_keys = {}
    if os.path.isfile(api_key_file):
        try:
            with open(api_key_file, "r") as f:
                for line in f:
                    line = line.strip()
                    if not line or "=" not in line:
                        continue
                    key, value = line.split("=", 1)
                    api_keys[key] = value
        except (FileNotFoundError, PermissionError) as e:
            print(f"Warning: Failed to load API key file {api_key_file}: {e}")
    else:
        print(f"Warning: Failed to load API keys from {api_key_file}")
    return api_keys

def load_json_file(json_file):
    if os.path.isfile(json_file):
        try:
            with open(json_file, "r") as f:
                return json.load(f)
        except (json.JSONDecodeError, FileNotFoundError, PermissionError) as e:
            print(f"Warning: Failed to load JSON file {json_file}: {e}")
    else:
        print(f"Warning: Failed to load JSON non existant file {json_file}")
    return {}

def main():
    parser = argparse.ArgumentParser(description="SpiderFoot Configuration Loader")
    parser.add_argument("-d", "--db", default=os.getenv("SPIDERFOOT_DB_PATH", "/var/lib/spiderfoot/spiderfoot.db"),
                        help="Path to SpiderFoot database")
    parser.add_argument("-c", "--config-dir", default=os.getenv("SPIDERFOOT_CONFIG_DIR", "configs"),
                        help="Directory containing configuration files")
    parser.add_argument("-f", "--json-file", default=os.getenv("SPIDERFOOT_JSON_FILE", ""),
                        help="Path to JSON configuration file")
    parser.add_argument("-i", "--import-api", default=os.getenv("SPIDERFOOT_API_KEYS", ""),
                        help="Path to SpiderFoot API key file")
    parser.add_argument("-j", "--json-string", default=os.getenv("SPIDERFOOT_JSON_STRING", ""),
                        help="JSON configuration string")
    parser.add_argument("-D", "--debug", action="store_true", default=os.getenv("SPIDERFOOT_DEBUG", "false").lower() == "true",
                        help="Enable debug mode")
    args = parser.parse_args()

    if args.debug:
        print(f"Debug: Database path: {args.db}")
        print(f"Debug: Config directory: {args.config_dir}")
        print(f"Debug: JSON file: {args.json_file}")
        print(f"Debug: JSON string: {args.json_string}")
        print(f"Debug: API key file: {args.import_api}")

    configs = load_configs(args.config_dir)
    if args.json_file:
        file_configs = load_json_file(args.json_file)
        configs.update(file_configs)

    if args.json_string:
        string_configs = load_json(args.json_string)
        configs.update(string_configs)

    if args.import_api:
        api_keys = load_api_keys(args.import_api)
        configs.update(api_keys)
    
    if args.debug:
        print(f"Config: {configs}")

    if configs:
        db = SpiderFootDb({"__database": args.db})
        db.configSet(configs)
        print("Loaded ALL configs")
    else:
        print("No valid configurations loaded.")

if __name__ == "__main__":
    main()


