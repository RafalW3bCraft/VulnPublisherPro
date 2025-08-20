#!/usr/bin/env python3
"""
Render.com Deployment Configuration for GitHub Repository Manager
Production-ready deployment with background automation
"""

import os
import sys
import logging
import time
from pathlib import Path

# Add project root to path
sys.path.insert(0, str(Path(__file__).parent.parent))

from core.github_api import GitHubAPI
from core.automation_manager import AutomationManager
from core.logger import Logger


class RenderDeployment:
    """Handles Render.com deployment and background automation"""
    
    def __init__(self):
        self.logger = Logger()
        self.setup_logging()
        
        # Verify environment variables
        self.verify_environment()
        
        # Initialize components
        try:
            self.github_api = GitHubAPI()
            
            # Validate token and auto-detect username if needed
            if not self.github_api.validate_token():
                self.logger.error("GitHub token validation failed - check token permissions")
                # Don't raise exception, but continue with limited functionality
                self.logger.warning("Continuing with limited functionality")
            
            self.automation_manager = AutomationManager(self.github_api)
            self.logger.info("Render deployment initialized successfully")
        except Exception as e:
            self.logger.error(f"Failed to initialize components: {e}")
            # Don't crash the deployment - log error and continue
            self.logger.warning("Deployment continuing with potential limitations")
            self.github_api = None
            self.automation_manager = None
    
    def setup_logging(self):
        """Setup logging for production environment"""
        logging.basicConfig(
            level=logging.INFO,
            format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
            handlers=[
                logging.StreamHandler(sys.stdout),
                logging.FileHandler('logs/automation.log', mode='a')
            ]
        )
        
        # Create logs directory if it doesn't exist
        Path('logs').mkdir(exist_ok=True)
    
    def verify_environment(self):
        """Verify required environment variables"""
        required_vars = ['GITHUB_TOKEN']
        optional_vars = ['DATABASE_URL', 'GITHUB_USERNAME']
        
        missing_vars = []
        for var in required_vars:
            if not os.getenv(var):
                missing_vars.append(var)
        
        if missing_vars:
            raise EnvironmentError(f"Missing required environment variables: {', '.join(missing_vars)}")
        
        # Warn about optional vars
        for var in optional_vars:
            if not os.getenv(var):
                self.logger.warning(f"{var} not set - using defaults or auto-detection")
        
        self.logger.info("Environment variables verified")
    
    def run_background_automation(self):
        """Run background automation for Render deployment"""
        try:
            self.logger.info("Starting GitHub Repository Manager automation on Render")
            
            # Check if automation manager is available
            if not self.automation_manager:
                self.logger.error("Automation manager not initialized - cannot start background automation")
                # Keep the process alive but in error state
                while True:
                    time.sleep(60)
                    self.logger.warning("Background process running in error state - check initialization")
                return
            
            # Start strategic automation in daemon mode
            result = self.automation_manager.start_strategic_automation(daemon=True)
            
            if result['status'] == 'started':
                self.logger.info("Strategic automation started successfully")
                
                # Keep the process alive
                import signal
                
                def signal_handler(signum, frame):
                    self.logger.info("Received shutdown signal, stopping automation...")
                    if self.automation_manager:
                        self.automation_manager.stop_automation()
                    sys.exit(0)
                
                signal.signal(signal.SIGINT, signal_handler)
                signal.signal(signal.SIGTERM, signal_handler)
                
                # Main loop - keeps service alive
                while True:
                    time.sleep(60)  # Check every minute
                    
                    # Enhanced health check with recovery
                    try:
                        status = self.automation_manager.get_comprehensive_status()
                        if status.get('status') != 'active':
                            self.logger.warning("Automation is not active, attempting restart...")
                            restart_result = self.automation_manager.start_strategic_automation(daemon=True)
                            if restart_result.get('status') != 'started':
                                self.logger.error(f"Failed to restart automation: {restart_result}")
                                # Implement exponential backoff for retries
                                time.sleep(min(300, 60 * 2**((time.time() % 7) // 1)))  # Max 5 min wait
                    except Exception as health_error:
                        self.logger.error(f"Health check failed: {health_error}")
                        # Continue running despite health check failures
                        continue
            else:
                self.logger.error(f"Failed to start automation: {result['message']}")
                sys.exit(1)
        
        except Exception as e:
            self.logger.error(f"Background automation failed: {e}")
            sys.exit(1)
    
    def run_web_interface(self):
        """Run web interface for monitoring (optional)"""
        try:
            from flask import Flask, jsonify, render_template_string
            
            app = Flask(__name__)
            
            @app.route('/')
            def dashboard():
                return render_template_string("""
                <!DOCTYPE html>
                <html>
                <head>
                    <title>GitHub Repository Manager</title>
                    <meta charset="utf-8">
                    <meta name="viewport" content="width=device-width, initial-scale=1">
                    <style>
                        body { font-family: Arial, sans-serif; margin: 20px; background: #f5f5f5; }
                        .container { max-width: 1200px; margin: 0 auto; background: white; padding: 20px; border-radius: 8px; }
                        .header { text-align: center; color: #333; margin-bottom: 30px; }
                        .status { padding: 15px; border-radius: 5px; margin: 10px 0; }
                        .active { background: #d4edda; border: 1px solid #c3e6cb; color: #155724; }
                        .stopped { background: #fff3cd; border: 1px solid #ffeaa7; color: #856404; }
                        .metric { display: inline-block; margin: 10px 20px; text-align: center; }
                        .metric-value { font-size: 2em; font-weight: bold; color: #007bff; }
                        .metric-label { color: #666; }
                    </style>
                </head>
                <body>
                    <div class="container">
                        <div class="header">
                            <h1>🚀 GitHub Repository Manager</h1>
                            <p>Strategic Follower Growth Automation</p>
                        </div>
                        <div id="status">Loading...</div>
                        <div id="metrics">Loading...</div>
                    </div>
                    <script>
                        function updateStatus() {
                            fetch('/api/status')
                                .then(response => response.json())
                                .then(data => {
                                    const statusDiv = document.getElementById('status');
                                    const statusClass = data.status === 'active' ? 'active' : 'stopped';
                                    statusDiv.innerHTML = `<div class="status ${statusClass}">Status: ${data.status.toUpperCase()}</div>`;
                                    
                                    const metricsDiv = document.getElementById('metrics');
                                    const metrics = data.github_metrics || {};
                                    metricsDiv.innerHTML = `
                                        <div class="metric">
                                            <div class="metric-value">${metrics.current_followers || 0}</div>
                                            <div class="metric-label">Followers</div>
                                        </div>
                                        <div class="metric">
                                            <div class="metric-value">${metrics.current_following || 0}</div>
                                            <div class="metric-label">Following</div>
                                        </div>
                                        <div class="metric">
                                            <div class="metric-value">${metrics.ratio || 0}</div>
                                            <div class="metric-label">Ratio</div>
                                        </div>
                                        <div class="metric">
                                            <div class="metric-value">${data.statistics?.success_rate || 0}%</div>
                                            <div class="metric-label">Success Rate</div>
                                        </div>
                                    `;
                                })
                                .catch(error => {
                                    document.getElementById('status').innerHTML = '<div class="status stopped">Error loading status</div>';
                                });
                        }
                        
                        updateStatus();
                        setInterval(updateStatus, 30000); // Update every 30 seconds
                    </script>
                </body>
                </html>
                """)
            
            @app.route('/api/status')
            def api_status():
                try:
                    if self.automation_manager:
                        status = self.automation_manager.get_comprehensive_status()
                        return jsonify(status)
                    else:
                        return jsonify({
                            'status': 'error', 
                            'message': 'Automation manager not initialized',
                            'github_metrics': {
                                'current_followers': 0,
                                'current_following': 0,
                                'ratio': 0
                            },
                            'statistics': {'success_rate': 0}
                        })
                except Exception as e:
                    return jsonify({
                        'status': 'error', 
                        'message': str(e),
                        'github_metrics': {
                            'current_followers': 0,
                            'current_following': 0,
                            'ratio': 0
                        },
                        'statistics': {'success_rate': 0}
                    }), 500
            
            @app.route('/health')
            def health():
                return jsonify({'status': 'healthy', 'timestamp': time.time()})
            
            # Run Flask app
            port = int(os.environ.get('PORT', 5000))
            app.run(host='0.0.0.0', port=port, debug=False)
        
        except Exception as e:
            self.logger.error(f"Web interface failed: {e}")
            # Fall back to background mode if web interface fails
            self.run_background_automation()


def main():
    """Main entry point for Render deployment"""
    try:
        deployment = RenderDeployment()
        
        # Check if we should run web interface or background automation
        mode = os.environ.get('DEPLOYMENT_MODE', 'web')
        
        if mode == 'background':
            deployment.run_background_automation()
        else:
            deployment.run_web_interface()
            
    except Exception as e:
        # Emergency fallback - start a minimal web server to prevent Bad Gateway
        print(f"CRITICAL ERROR: Deployment failed: {e}")
        print("Starting emergency fallback web server...")
        
        from flask import Flask, jsonify
        
        app = Flask(__name__)
        
        @app.route('/')
        def emergency_status():
            return f"""
            <html>
            <head><title>GitHub Repository Manager - Startup Error</title></head>
            <body style="font-family: Arial; padding: 20px; background: #ffebee;">
                <h1 style="color: #c62828;">🚨 Deployment Error</h1>
                <p><strong>Error:</strong> {str(e)}</p>
                <p><strong>Status:</strong> Service failed to initialize properly</p>
                <p><strong>Action Required:</strong> Check environment variables and GitHub token</p>
                <hr>
                <h3>Troubleshooting Steps:</h3>
                <ol>
                    <li>Verify GITHUB_TOKEN is set correctly</li>
                    <li>Check token has required permissions</li>
                    <li>Ensure DATABASE_URL is accessible</li>
                    <li>Review build logs for specific errors</li>
                </ol>
                <p><em>Timestamp: {time.strftime('%Y-%m-%d %H:%M:%S UTC')}</em></p>
            </body>
            </html>
            """
        
        @app.route('/health')
        def emergency_health():
            return jsonify({
                'status': 'error', 
                'message': 'Deployment failed - emergency mode',
                'timestamp': time.time()
            })
        
        @app.route('/api/status')
        def emergency_api():
            return jsonify({
                'status': 'error',
                'message': f'Deployment initialization failed: {str(e)}',
                'github_metrics': {'current_followers': 0, 'current_following': 0, 'ratio': 0},
                'statistics': {'success_rate': 0}
            })
        
        # Start emergency server on port 5000
        port = int(os.environ.get('PORT', 5000))
        print(f"Emergency server starting on port {port}")
        app.run(host='0.0.0.0', port=port, debug=False)


if __name__ == "__main__":
    main()