from __future__ import annotations

from flask_deck.demo import create_demo_app

app = create_demo_app()

if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5055, debug=False)
