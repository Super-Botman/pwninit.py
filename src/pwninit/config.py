import os
from pathlib import Path
from pwn import log


class Config:
    def __init__(self):
        self.config_file = Path.home() / '.config' / 'pwninit.conf'
        self._config_data = {}
        self._load_config()

    def _load_config(self):
        if self.config_file.exists():
            try:
                with open(self.config_file, 'r') as f:
                    for line in f:
                        line = line.strip()
                        if line and not line.startswith('#') and '=' in line:
                            key, value = line.split('=', 1)
                            self._config_data[key.strip(
                            )] = value.strip().strip('"\'')
            except Exception as e:
                log.warning(f"Error reading config file {
                            self.config_file}: {e}")

    def get(self, key, default=None, env_var=None):
        if env_var and env_var in os.environ:
            return os.environ[env_var]

        return self._config_data.get(key, default)

    def get_author(self):
        return self.get('author', '0xB0tm4n', 'PWNINIT_AUTHOR')

    def get_rootme_api_key(self):
        api_key = self.get('rootme_api_key', env_var='ROOTME_API_KEY')
        if not api_key:
            raise ValueError(
                "Root-me API key not found. Set ROOTME_API_KEY environment variable or add rootme_api_key=your_key to ~/.config/pwninit.conf")
        return api_key

    def create_default_config(self):
        self.config_file.parent.mkdir(parents=True, exist_ok=True)

        default_config = """# pwninit configuration file
# You can override these values with environment variables

# Author name for generated files
author=0xB0tm4n

# Root-me provider settings
# rootme_api_key=your_api_key_here
"""

        if not self.config_file.exists():
            try:
                with open(self.config_file, 'w') as f:
                    f.write(default_config)
                log.success(f"Created default config file at {
                            self.config_file}")
            except Exception as e:
                log.warning(f"Could not create config file: {e}")


config = Config()
