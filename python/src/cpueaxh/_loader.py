import os
from pathlib import Path


def default_library_path() -> Path:
    env_path = os.environ.get("CPUEAXH_DLL_PATH")
    if env_path:
        return Path(env_path)

    root = Path(__file__).resolve().parents[3]
    candidates = [
        root / "build" / "Debug" / "cpueaxh_shared.dll",
        root / "build" / "Release" / "cpueaxh_shared.dll",
        root / "build-cmake" / "Debug" / "cpueaxh_shared.dll",
        root / "build-cmake" / "Release" / "cpueaxh_shared.dll",
        root / "build-py" / "Debug" / "cpueaxh_shared.dll",
        root / "build-py" / "Release" / "cpueaxh_shared.dll",
        root / "x64" / "Debug" / "cpueaxh_shared.dll",
        root / "x64" / "Release" / "cpueaxh_shared.dll",
        root / "cpueaxh_shared.dll",
    ]
    for candidate in candidates:
        if candidate.exists():
            return candidate
    return candidates[-1]
