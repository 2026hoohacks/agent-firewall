"""Entry point: ``python -m agentguard``."""

import uvicorn

from agentguard.api.app import create_app

app = create_app()

if __name__ == "__main__":
    uvicorn.run(
        "agentguard.__main__:app",
        host="0.0.0.0",
        port=8000,
        reload=True,
    )
