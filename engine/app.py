from flask import Flask
from dotenv import load_dotenv
import logging
import config

logging.basicConfig(level=logging.INFO)


def create_app() -> Flask:
    """Create and configure the Flask app instance."""
    load_dotenv()

    app = Flask(__name__)
    app.config['APP_CONFIG'] = config.Config()

    from controllers.config_controller import config_blueprint

    app.register_blueprint(config_blueprint)
    return app


app = create_app()


if __name__ == '__main__':
    app.run(host='0.0.0.0', port=app.config['APP_CONFIG'].API_PORT, debug=False)
