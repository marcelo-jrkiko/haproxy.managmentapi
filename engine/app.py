from flask import Flask
from flask_cors import CORS
from dotenv import load_dotenv
import logging
import config
import Scheduler

logging.basicConfig(level=logging.INFO)

def create_app() -> Flask:
    """Create and configure the Flask app instance."""
    load_dotenv()

    app = Flask(__name__)
    app.config['APP_CONFIG'] = config.Config()

    CORS(
        app,
        resources={r"/*": {"origins": app.config['APP_CONFIG'].CORS_ORIGINS}},
        supports_credentials=app.config['APP_CONFIG'].CORS_SUPPORTS_CREDENTIALS,
    )

    from controllers.logs_controller import logs_bp
    from controllers.config_controller import config_blueprint   
    
    app.register_blueprint(logs_bp)
    app.register_blueprint(config_blueprint)
    
    scheduler = Scheduler(app)
    scheduler.start()    
    
    return app


app = create_app()


if __name__ == '__main__':
    app.run(host='0.0.0.0', port=app.config['APP_CONFIG'].API_PORT, debug=False)
