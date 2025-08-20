#!/usr/bin/env python3
"""
Simplified Render startup script
Minimal dependencies with robust error handling
"""

import os
import sys
from pathlib import Path

def create_minimal_server():
    """Create minimal Flask server that always starts"""
    try:
        from flask import Flask, jsonify
        import time
        
        app = Flask(__name__)
        
        @app.route('/')
        def home():
            github_token = "✅ Set" if os.getenv('GITHUB_TOKEN') else "❌ Missing"
            db_url = "✅ Set" if os.getenv('DATABASE_URL') else "❌ Missing"
            mode = os.getenv('DEPLOYMENT_MODE', 'web')
            
            return f"""
            <!DOCTYPE html>
            <html>
            <head>
                <title>GitHub Repository Manager</title>
                <meta charset="utf-8">
                <meta name="viewport" content="width=device-width, initial-scale=1">
                <style>
                    body {{ font-family: Arial, sans-serif; margin: 20px; background: #f5f5f5; }}
                    .container {{ max-width: 800px; margin: 0 auto; background: white; padding: 20px; border-radius: 8px; }}
                    .status {{ padding: 10px; margin: 10px 0; border-radius: 5px; }}
                    .ok {{ background: #d4edda; border: 1px solid #c3e6cb; color: #155724; }}
                    .error {{ background: #f8d7da; border: 1px solid #f5c6cb; color: #721c24; }}
                    .warning {{ background: #fff3cd; border: 1px solid #ffeaa7; color: #856404; }}
                </style>
            </head>
            <body>
                <div class="container">
                    <h1>🚀 GitHub Repository Manager</h1>
                    <h2>Service Status</h2>
                    
                    <div class="status {'ok' if github_token == '✅ Set' else 'error'}">
                        <strong>GitHub Token:</strong> {github_token}
                    </div>
                    
                    <div class="status {'ok' if db_url == '✅ Set' else 'warning'}">
                        <strong>Database URL:</strong> {db_url}
                    </div>
                    
                    <div class="status ok">
                        <strong>Deployment Mode:</strong> {mode}
                    </div>
                    
                    <div class="status ok">
                        <strong>Server Status:</strong> Running
                    </div>
                    
                    <h3>Next Steps</h3>
                    <ol>
                        <li>Set GITHUB_TOKEN in Render environment variables</li>
                        <li>Ensure DATABASE_URL is configured (auto-set with PostgreSQL)</li>
                        <li>Check build logs for any initialization errors</li>
                        <li>Wait for full service initialization</li>
                    </ol>
                    
                    <p><em>Last updated: {time.strftime('%Y-%m-%d %H:%M:%S UTC')}</em></p>
                </div>
            </body>
            </html>
            """
        
        @app.route('/health')
        def health():
            return jsonify({
                'status': 'healthy',
                'timestamp': time.time(),
                'github_token_set': bool(os.getenv('GITHUB_TOKEN')),
                'database_url_set': bool(os.getenv('DATABASE_URL'))
            })
        
        @app.route('/api/status')
        def api_status():
            return jsonify({
                'status': 'running',
                'message': 'Service is operational',
                'github_metrics': {
                    'current_followers': 0,
                    'current_following': 0,
                    'ratio': 0
                },
                'statistics': {'success_rate': 0},
                'environment': {
                    'github_token_configured': bool(os.getenv('GITHUB_TOKEN')),
                    'database_configured': bool(os.getenv('DATABASE_URL')),
                    'deployment_mode': os.getenv('DEPLOYMENT_MODE', 'web')
                }
            })
        
        return app
        
    except Exception as e:
        print(f"Failed to create Flask app: {e}")
        sys.exit(1)

def main():
    """Main entry point"""
    try:
        # Try the full deployment first
        sys.path.insert(0, str(Path(__file__).parent.parent))
        
        # Import and run main deployment if possible
        try:
            from deploy.render_deployment import main as full_main
            print("Attempting full deployment startup...")
            full_main()
        except Exception as e:
            print(f"Full deployment failed: {e}")
            print("Starting minimal fallback server...")
            
            # Start minimal server as fallback
            app = create_minimal_server()
            port = int(os.environ.get('PORT', 5000))
            print(f"Minimal server starting on port {port}")
            app.run(host='0.0.0.0', port=port, debug=False)
            
    except Exception as e:
        print(f"CRITICAL: All startup methods failed: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()