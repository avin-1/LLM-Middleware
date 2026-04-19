from enum import Enum
from typing import List, Any

class Profile(Enum):
    LITE = "lite"
    STANDARD = "standard"
    ENTERPRISE = "enterprise"

class EngineRegistry:
    def __init__(self):
        self._profile = Profile.STANDARD

    @property
    def profile(self) -> Profile:
        return self._profile

    @profile.setter
    def profile(self, value: Profile):
        self._profile = value

    def get_engines_for_profile(self) -> List[str]:
        # Return common engines
        return ["injection", "query", "behavioral", "qwen_guard"]

def get_registry():
    return EngineRegistry()
