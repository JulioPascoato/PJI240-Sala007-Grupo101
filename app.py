from flask import Flask, render_template, abort, redirect, url_for, flash
from flask_bootstrap import Bootstrap
from flask_ckeditor import CKEditor
from functools import wraps
from forms import UsersForm, LoginForm
from database import User, engine, Base, Session
from flask_login import UserMixin, login_user, LoginManager, login_required, current_user, logout_user
from werkzeug.security import generate_password_hash, check_password_hash



app = Flask(__name__)
app.config['SECRET_KEY'] = '8BYkEfBA6O6donzWlSihBXox7C0sKR6b'
ckeditor = CKEditor(app)
Bootstrap(app)
login_manager = LoginManager()
login_manager.init_app(app)

local_session=Session(bind=engine)

#Base.metadata.create_all(engine)

@login_manager.user_loader
def load_user(user_id):
    return local_session.query(User).get(int(user_id))


def admin_only(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if current_user.id != 1:
            return abort(403)
        return f(*args, **kwargs)
    return decorated_function


@app.route("/")
def home():
    return render_template("index.html")

@app.route('/login', methods=["GET", "POST"])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        email = form.email.data
        password = form.password.data

        user = local_session.query(User).filter_by(email=email).first()
        print(user)
        # Email doesn't exist or password incorrect.
        if not user:
            flash("E-mail não existe, Por gentileza tente novamente.")
            return redirect(url_for('login'))
        elif not check_password_hash(user.password, password):
            flash('Senha incorreta, Por gentileza tente novamente.')
            return redirect(url_for('login'))
        else:
            login_user(user)
            return redirect(url_for('admin'))
    return render_template("login.html", form=form, current_user=current_user)


@app.route("/users", methods=["GET", "POST"])
@login_required
def users():
    form = UsersForm()
    if form.validate_on_submit():

        if local_session.query(User).filter_by(email=form.email.data).first():
            print(local_session.query(User).filter_by(email=form.email.data).first())
            #User already exists
            flash("E-mail já cadastrado, Efetue o login!")
            return redirect(url_for('login'))

        hash_and_salted_password = generate_password_hash(
            form.password.data,
            method='pbkdf2:sha256',
            salt_length=8
        )
        new_user = User(
            fullname=form.fullname.data,
            email=form.email.data,
            password=hash_and_salted_password,
        )
        local_session.add(new_user)
        local_session.commit()
        login_user(new_user)
        return redirect(url_for("home"))

    return render_template("users.html", form=form, current_user=current_user)


@app.route('/admin')
@login_required
def admin():
    return render_template("admin.html", current_user=current_user)


@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('home'))


if __name__ == "__main__":
    app.run(debug=True)
