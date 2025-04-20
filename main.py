from app import app, socketio

# Ensure that we initialize everything properly
if __name__ == '__main__':
    # Use socketio.run instead of app.run for proper WebSocket support
    socketio.run(app, host='0.0.0.0', port=5000, debug=True, allow_unsafe_werkzeug=True)
