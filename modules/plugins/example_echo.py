"""Example user plugin — copy & adapt in modules/plugins/."""

PLUGIN = {
    "id": "example_echo",
    "name": "Example Echo",
    "description": "Demo plugin that echoes the target",
}


def run(target: str, options: dict) -> dict:
    return {
        "plugin": PLUGIN["id"],
        "target": target,
        "options": options,
        "message": f"Plugin received target: {target}",
    }
