#!/usr/bin/env python3
"""
Emergency fallback server for Render deployment
Provides minimal web interface when main deployment fails
"""

import os
import time
from flask import Flask, jsonify

def create_emergency_app():
    """Create emergency Flask app"""
    app = Flask(__name__)
    
    @app.route('/')
    def emergency_status():
        return f"""
        <html>
        <head>
            <title>GitHub Repository Manager - Initializing</title>
            <meta http-equiv="refresh" content="30">
        </head>
        <body style="font-family: Arial; padding: 20px; background: #fff3cd;">
            <h1 style="color: #856404;">⚠️ Service Initializing</h1>
            <p><strong>Status:</strong> GitHub Repository Manager is starting up</p>
            <p><strong>Mode:</strong> Emergency fallback server</p>
            <p><strong>Action:</strong> Please check environment variables and GitHub token</p>
            <hr>
            <h3>Required Configuration:</h3>
            <ul>
                <li>GITHUB_TOKEN - Set in Render environment variables</li>
                <li>DEPLOYMENT_MODE - Set to 'web' for web service</li>
                <li>DATABASE_URL - Auto-configured by Render PostgreSQL</li>
            </ul>
            <p><strong>Automatic refresh in 30 seconds...</strong></p>
            <p><em>Timestamp: {time.strftime('%Y-%m-%d %H:%M:%S UTC')}</em></p>
        </body>
        </html>
        """
    
    @app.route('/health')
    def health():
        return jsonify({
            'status': 'initializing',
            'message': 'Service starting up',
            'timestamp': time.time()
        })
    
    @app.route('/api/status')
    def api_status():
        return jsonify({
            'status': 'initializing',
            'message': 'GitHub Repository Manager starting up',
            'github_metrics': {
                'current_followers': 0,
                'current_following': 0,
                'ratio': 0
            },
            'statistics': {'success_rate': 0}
        })
    
    return app

if __name__ == "__main__":
    app = create_emergency_app()
    port = int(os.environ.get('PORT', 5000))
    print(f"Emergency server starting on port {port}")
    app.run(host='0.0.0.0', port=port, debug=False)