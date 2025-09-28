# Python-Chat-Onyx
This project was created during an internship at Onyx Company. It is a simple chat application built using WebSockets and the Flask framework.


## Technologies Used

### Backend
- **Flask** - Python web framework
- **Flask-SocketIO** - WebSocket support for real-time communication
- **Flask-SQLAlchemy** - ORM for database operations
- **SQLite** - Lightweight database for data storage
- **Werkzeug** - Password hashing and security utilities

### Frontend
- **HTML5** - Markup language
- **Bootstrap 5** - CSS framework for responsive design
- **JavaScript** - Client-side functionality
- **Socket.IO Client** - WebSocket client library

### Additional Libraries
- **python-socketio** - Server-side WebSocket implementation
- **python-engineio** - Engine.IO server

## Installation

1. **Clone the repository**
   ```bash
   https://github.com/Kp-os/Python-Chat-Onyx
   cd Python-Chat-Onyx
   ```

2. **Create a virtual environment (recommended)**
   ```bash
   python -m venv venv
   source venv/bin/activate  # On Windows: venv\\Scripts\\activate
   ```

3. **Install dependencies**
   ```bash
   pip install -r requirements.txt
   ```

## Running the Application

### Method 1: Direct execution
```bash
python app.py
```

### Method 2: Using the run script
```bash
python scripts/run_server.py
```

The server will start on `http://localhost:5000`

## Usage

1. **Registration/Login**
   - Enter your username on the main page
   - If the username doesn't exist, you'll be prompted to create a password
   - If it exists, enter your password to log in

2. **Creating Chat Rooms**
   - Click "Create Room" on the dashboard
   - Enter a room name
   - Share the generated invite code with others

3. **Joining Chat Rooms**
   - Enter an invite code in the "Join Room" section
   - Click "Join" to enter the room

4. **Chatting**
   - Select a room from your dashboard
   - Start typing messages in real-time
   - See when users join/leave the room
