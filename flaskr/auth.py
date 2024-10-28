import functools

from flask import (
    Blueprint, flash, g, redirect, render_template, request, session, url_for
)
from werkzeug.security import check_password_hash, generate_password_hash

from flaskr.db import get_db

bp = Blueprint('auth', __name__, url_prefix='/auth')

@bp.route('/register', methods=('GET', 'POST'))
def register():
    if request.method == 'POST':
        username = request.form['username']
        email = request.form['email']
        password = request.form['password']
        veri_password = request.form['veri_password']
        
        db = get_db()
        error = None

        if not username:
            error = 'Se requiere un usuario.'
        elif not password:
            error = 'Se requiere una contraseña.'
        elif not email:
            error = 'Se requiere un email.'
        elif veri_password != password:
            error = 'Las contraseñas no coinciden.'    

        if error is None:
            try:
                db.execute(
                    "INSERT INTO user (username, email, password, veri_password) VALUES (?, ?, ?, ?)",
                    (username, email, generate_password_hash(password), veri_password),
                )
                db.commit()
            except db.IntegrityError:
                error = f"El usuario {username} ya esta registrado."
            else:
                return redirect(url_for("auth.login"))

        flash(error)

    return render_template('auth/register.html')

@bp.route('/login', methods=('GET', 'POST'))
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        db = get_db()
        error = None
        user = db.execute(
            'SELECT * FROM user WHERE username = ?', (username,)
        ).fetchone()

        if user is None:
            error = 'Usuario incorrecto.'
        elif not check_password_hash(user['password'], password):
            error = 'Contraseña incorrecta.'

        if error is None:
            session.clear()
            session['user_id'] = user['id']
            return redirect(url_for('index'))

        flash(error)

    return render_template('auth/login.html')

@bp.before_app_request
def load_logged_in_user():
    user_id = session.get('user_id')

    if user_id is None:
        g.user = None
    else:
        g.user = get_db().execute(
            'SELECT * FROM user WHERE id = ?', (user_id,)
        ).fetchone()

@bp.route('/modifEmail', methods=('GET', 'POST'))
def chEmail():
    if request.method == 'POST':
        email = request.form['new_email']
        error = None
        db = get_db()
        if not email:
            error = 'Se requiere el email.'

        if error is None:
            db.execute(
                'UPDATE user SET email = ?'
                ' WHERE id = ?',
                (email, g.user["id"],)
            )
            db.commit()
            return redirect(url_for('index'))

    return render_template('auth/modifEmail.html')

@bp.route('/delUser', methods=('GET', 'POST'))
def delUser():
    if request.method == 'POST':
        
        error = None
        db = get_db()
        if error is None:
            db.execute(
                'DELETE FROM user WHERE id = ?',
                (g.user["id"],)
            )
            db.commit()
            session.clear()
            return redirect(url_for('index'))

    return render_template('auth/modifEmail.html')

@bp.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('index'))

def login_required(view):
    @functools.wraps(view)
    def wrapped_view(**kwargs):
        if g.user is None:
            return redirect(url_for('auth.login'))

        return view(**kwargs)

    return wrapped_view

 #blueprint
    from . import auth
    app.register_blueprint(auth.bp)

