from flask import Flask, render_template, request, redirect, url_for, session, flash, jsonify
from flask_socketio import SocketIO, emit, join_room, leave_room
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
import random
import logging
import os
from datetime import datetime
import uuid

app = Flask(__name__)
app.config['SECRET_KEY'] = 'your-secret-key-here'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///chat.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)
socketio = SocketIO(app, cors_allowed_origins="*")

if not os.path.exists('chat_logs'):
    os.makedirs('chat_logs')


class User(db.Model):
    """
    Model representing a user in the chat application.
    """
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password_hash = db.Column(db.String(120), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    owned_rooms = db.relationship('ChatRoom', backref='owner', lazy=True)
    memberships = db.relationship('RoomMembership', backref='user', lazy=True)


class ChatRoom(db.Model):
    """
    Model representing a chat room.
    """
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    invite_code = db.Column(db.String(36), unique=True, nullable=False)
    owner_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    memberships = db.relationship('RoomMembership', backref='room', lazy=True, cascade='all, delete-orphan')


class RoomMembership(db.Model):
    """
    Model representing a user's membership in a chat room.
    """
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    room_id = db.Column(db.Integer, db.ForeignKey('chat_room.id'), nullable=False)
    joined_at = db.Column(db.DateTime, default=datetime.utcnow)

    __table_args__ = (db.UniqueConstraint('user_id', 'room_id'),)


user_colors = {}


def get_user_color(username):
    """
    Returns a unique color for each user based on their username.
    :param username: username of the user
    :return: color code as a string
    """
    if username not in user_colors:
        colors = [
            '#FF6B6B', '#4ECDC4', '#45B7D1', '#96CEB4', '#FFEAA7',
            '#DDA0DD', '#98D8C8', '#F7DC6F', '#BB8FCE', '#85C1E9',
            '#F8C471', '#82E0AA', '#F1948A', '#85C1E9', '#D7BDE2'
        ]
        user_colors[username] = random.choice(colors)
    return user_colors[username]


def log_message(room_name, username, message):
    """
    Creates or appends a message to the chat log file for the specified room.
    :param room_name: name of the chat room
    :param username: username of the user
    :param message: content of the message
    :return: None
    """
    log_filename = f'chat_logs/{room_name}.log'
    timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')

    logger = logging.getLogger(f'room_{room_name}')
    logger.setLevel(logging.INFO)

    if not logger.handlers:
        handler = logging.FileHandler(log_filename, encoding='utf-8')
        formatter = logging.Formatter('%(message)s')
        handler.setFormatter(formatter)
        logger.addHandler(handler)

    logger.info(f'[{timestamp}] {username}: {message}')


# Routes
@app.route('/')
def index():
    """
    Main page with login and registration options.
    :return:
    Rendered login page or redirect to dashboard if user is already logged in.
    """
    if 'user_id' in session:
        return redirect(url_for('dashboard'))
    return render_template('login.html')


@app.route('/login', methods=['POST'])
def login():
    """
    Handles user login.
    :return:
    Redirects to dashboard on successful login or back to index with error message.
    """
    username = request.form['username']
    password = request.form['password']

    user = User.query.filter_by(username=username).first()

    if user and check_password_hash(user.password_hash, password):
        session['user_id'] = user.id
        session['username'] = user.username
        return redirect(url_for('dashboard'))
    else:
        flash('Невірний логін або пароль')
        return redirect(url_for('index'))


@app.route('/register', methods=['POST'])
def register():
    """
    Handles user registration.
    :return: redirects to dashboard on successful registration or back to index with error message.
    """
    username = request.form['username']
    password = request.form['password']

    if User.query.filter_by(username=username).first():
        flash('Користувач з таким іменем вже існує')
        return redirect(url_for('index'))

    password_hash = generate_password_hash(password)
    user = User(username=username, password_hash=password_hash)
    db.session.add(user)
    db.session.commit()

    session['user_id'] = user.id
    session['username'] = user.username
    flash('Реєстрація успішна!')
    return redirect(url_for('dashboard'))


@app.route('/dashboard')
def dashboard():
    """
    User dashboard showing owned and joined chat rooms.
    :return: rendered dashboard page with user's rooms and owned rooms.
    """
    if 'user_id' not in session:
        return redirect(url_for('index'))

    user = User.query.get(session['user_id'])

    user_rooms = db.session.query(ChatRoom).join(RoomMembership).filter(
        RoomMembership.user_id == user.id
    ).all()

    owned_rooms = ChatRoom.query.filter_by(owner_id=user.id).all()

    return render_template('dashboard.html',
                           user=user,
                           user_rooms=user_rooms,
                           owned_rooms=owned_rooms)


@app.route('/check_user', methods=['POST'])
def check_user():
    """
    Checks if a username already exists in the database.
    :return: JSON response indicating whether the username exists.
    """
    data = request.get_json()
    username = data.get('username')

    user = User.query.filter_by(username=username).first()
    return jsonify({'exists': user is not None})


@app.route('/create_room', methods=['POST'])
def create_room():
    """
    Handles the creation of a new chat room.
    :return: redirects to dashboard with success message or back to dashboard with error.
    """
    if 'user_id' not in session:
        return redirect(url_for('index'))

    room_name = request.form['room_name']
    invite_code = str(uuid.uuid4())

    room = ChatRoom(
        name=room_name,
        invite_code=invite_code,
        owner_id=session['user_id']
    )
    db.session.add(room)
    db.session.commit()

    membership = RoomMembership(user_id=session['user_id'], room_id=room.id)
    db.session.add(membership)
    db.session.commit()

    flash(f'Кімната "{room_name}" створена! Код запрошення: {invite_code}')
    return redirect(url_for('dashboard'))


@app.route('/join_room', methods=['POST'])
def join_room_route():
    """
    Handles joining an existing chat room using an invite code.
    :return: redirects to dashboard with success message or back to dashboard with error.
    """
    if 'user_id' not in session:
        return redirect(url_for('index'))

    invite_code = request.form['invite_code']
    room = ChatRoom.query.filter_by(invite_code=invite_code).first()

    if not room:
        flash('Невірний код запрошення')
        return redirect(url_for('dashboard'))

    existing_membership = RoomMembership.query.filter_by(
        user_id=session['user_id'],
        room_id=room.id
    ).first()

    if existing_membership:
        flash('Ви вже є учасником цієї кімнати')
        return redirect(url_for('dashboard'))

    membership = RoomMembership(user_id=session['user_id'], room_id=room.id)
    db.session.add(membership)
    db.session.commit()

    flash(f'Ви приєдналися до кімнати "{room.name}"')
    return redirect(url_for('dashboard'))


@app.route('/chat/<int:room_id>')
def chat_room(room_id):
    """
    Renders the chat room page for a specific room.
    :param room_id: id of the chat room
    :return: rendered chat room page or redirects to dashboard with error if access is denied.
    """
    if 'user_id' not in session:
        return redirect(url_for('index'))

    membership = RoomMembership.query.filter_by(
        user_id=session['user_id'],
        room_id=room_id
    ).first()

    if not membership:
        flash('У вас немає доступу до цієї кімнати')
        return redirect(url_for('dashboard'))

    room = ChatRoom.query.get_or_404(room_id)
    return render_template('chat.html', room=room)


@app.route('/logout')
def logout():
    """
    Handles user logout by clearing the session.
    :return: redirects to the index page.
    """
    session.clear()
    return redirect(url_for('index'))


# WebSocket обробники
@socketio.on('connect')
def on_connect():
    """
    Handles user connection to the WebSocket.
    :return: None
    """
    if 'user_id' not in session:
        return False
    print(f'Користувач {session["username"]} підключився')


@socketio.on('disconnect')
def on_disconnect():
    """
    Handles user disconnection from the WebSocket.
    :return: None
    """
    if 'username' in session:
        print(f'Користувач {session["username"]} відключився')


@socketio.on('join')
def on_join(data):
    """
    Handles user joining a chat room.
    :param data: contains room id and other data
    :return: None
    """
    if 'user_id' not in session:
        return

    room_id = data['room']
    username = session['username']

    membership = RoomMembership.query.filter_by(
        user_id=session['user_id'],
        room_id=room_id
    ).first()

    if not membership:
        return

    room = ChatRoom.query.get(room_id)
    join_room(str(room_id))

    user_color = get_user_color(username)
    emit('status', {
        'msg': f'{username} приєднався до чату',
        'username': username,
        'color': user_color,
        'type': 'join'
    }, room=str(room_id))

    log_message(room.name, 'SYSTEM', f'{username} приєднався до чату')


@socketio.on('leave')
def on_leave(data):
    """
    Handles user leaving a chat room.
    :param data: contains room id and other data
    :return: None
    """
    if 'user_id' not in session:
        return

    room_id = data['room']
    username = session['username']
    room = ChatRoom.query.get(room_id)

    leave_room(str(room_id))

    user_color = get_user_color(username)
    emit('status', {
        'msg': f'{username} покинув чат',
        'username': username,
        'color': user_color,
        'type': 'leave'
    }, room=str(room_id))

    log_message(room.name, 'SYSTEM', f'{username} покинув чат')


@socketio.on('message')
def handle_message(data):
    """
    Handles incoming chat messages from users.
    :param data: contains room id and message content
    :return: None
    """
    if 'user_id' not in session:
        return

    room_id = data['room']
    message = data['message']
    username = session['username']

    membership = RoomMembership.query.filter_by(
        user_id=session['user_id'],
        room_id=room_id
    ).first()

    if not membership:
        return

    room = ChatRoom.query.get(room_id)
    user_color = get_user_color(username)

    emit('message', {
        'username': username,
        'message': message,
        'color': user_color,
        'timestamp': datetime.now().strftime('%H:%M:%S')
    }, room=str(room_id))

    log_message(room.name, username, message)


if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    socketio.run(app, debug=True, host='0.0.0.0', port=5000)
