from datetime import datetime
from flask import Flask, render_template, abort, redirect, url_for, flash
from flask_bootstrap import Bootstrap
from flask_ckeditor import CKEditor
from functools import wraps
from forms import UsersForm, LoginForm, MidiaForm, ProtagonistaForm, SuporteForm, AcervoForm, SearchForm
from database import Midia, User, Protagonista, Suporte, Acervo, Base, engine, Session
from flask_login import login_user, LoginManager, login_required, current_user, logout_user
from werkzeug.security import generate_password_hash, check_password_hash
from sqlalchemy.orm import joinedload

app = Flask(__name__)
app.config['SECRET_KEY'] = '8BYkEfBA6O6donzWlSihBXox7C0sKR6b'
ckeditor = CKEditor(app)
Bootstrap(app)
login_manager = LoginManager()
login_manager.init_app(app)

local_session=Session(bind=engine)

Base.metadata.create_all(engine)

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


@app.route("/", methods=["GET", "POST"])
def home():
    form = LoginForm()

    if form.validate_on_submit():
        email = form.email.data
        password = form.password.data

        user = local_session.query(User).filter_by(email=email).first()
        
        #print(user)
        # Email doesn't exist or password incorrect.
        if not user:
            flash("Usuário não existe, Por gentileza tente novamente.")
            return redirect(url_for('home'))
        elif not check_password_hash(user.password, password):
            flash('Senha incorreta, Por gentileza tente novamente.')
            return redirect(url_for('home'))
        else:
            login_user(user)
            flash(f"Bem-vindo a área administrativa, {user.fullname}")
            return redirect(url_for('admin'))

    return render_template("index.html", form=form)

@app.route("/acessibilidade")
def acessibilidade():
    return render_template("acessibilidade.html")

###### Login Admin ####### 
@app.route('/login', methods=["GET", "POST"])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        email = form.email.data
        password = form.password.data

        user = local_session.query(User).filter_by(email=email).first()
        
        #print(user)
        # Email doesn't exist or password incorrect.
        if not user:
            flash("Usuário não existe, Por gentileza tente novamente.")
            return redirect(url_for('login'))
        elif not check_password_hash(user.password, password):
            flash('Senha incorreta, Por gentileza tente novamente.')
            return redirect(url_for('login'))
        else:
            login_user(user)
            flash(f"Bem-vindo a área administrativa, {user.fullname}")
            return redirect(url_for('admin'))
    return render_template("login.html", form=form, current_user=current_user)


@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('home'))


###### Admin ######
@app.route('/admin')
@login_required
def admin():
    return render_template("admin.html", current_user=current_user)


###### Usuarios ####### 
@app.route('/user-admin')
@login_required
def user_admin():
    users = local_session.query(User).all()
    #print(users)
    return render_template("user_admin.html", current_user=current_user, users=users)
    
@app.route("/users", methods=["GET", "POST"])
#@login_required
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

        try:
            local_session.commit()
            flash("Usuário cadastrado com sucesso!")
        except:
            flash("Impossivel cadastrar novo usuário. Tente Novamente!")

        if not current_user.is_authenticated:
            login_user(new_user)
        return redirect(url_for("admin"))

    return render_template("users.html", form=form, current_user=current_user)


@app.route("/delete-user/<int:user_id>")
@login_required
def delete_user(user_id):
    user_to_delete = local_session.query(User).get(user_id)
    local_session.delete(user_to_delete)
    
    try:
        local_session.commit()
        flash("Deletado com sucesso!")
    except:
        flash("Impossivel deletar. Tente Novamente!")
    
    return redirect(url_for('user_admin'))


###### Tipos de midia #####
@app.route("/midia", methods=["GET", "POST"])
@login_required
def midia():
    form = MidiaForm()
    if form.validate_on_submit():

        if local_session.query(Midia).filter_by(name=form.name.data).first():
            
            #Midia already exists
            flash("Tipo de mídia já cadastrado!")
            return redirect(url_for('midia'))

        new_midia = Midia(
            name=form.name.data,
        )
        local_session.add(new_midia)
        try:
            local_session.commit()
            flash("Adicionado com sucesso!")
        except:
            flash("Impossivel adicionar. Tente Novamente!")
        
        return redirect(url_for("midia_admin"))

    return render_template("midia.html", form=form, current_user=current_user)

@app.route('/midia-admin')
@login_required
def midia_admin():
    midias = local_session.query(Midia).all()
    return render_template("midia_admin.html", current_user=current_user, midias=midias)


@app.route("/edit-midia/<int:midia_id>", methods=["GET", "POST"])
def edit_midia(midia_id):
    midia = local_session.query(Midia).get(midia_id)
    edit_midia = MidiaForm(
        name=midia.name
    )

    if edit_midia.validate_on_submit():
        midia.name = edit_midia.name.data
        try:
            local_session.commit()
            flash("Modificado com sucesso!")
        except:
            flash("Impossivel modificar. Tente Novamente!")

        return redirect(url_for("midia_admin", midia_id=midia.id))

    return render_template("midia.html", form=edit_midia, is_edit=True)


@app.route("/delete-midia/<int:midia_id>")
@login_required
def delete_midia(midia_id):
    midia_to_delete = local_session.query(Midia).get(midia_id)
    local_session.delete(midia_to_delete)

    try:
        local_session.commit()
        flash("Deletado com sucesso!")
    except:
        flash("Impossivel deletar. Tente Novamente!")

    return redirect(url_for('midia_admin'))


###### Protagonista #####
@app.route("/protagonista", methods=["GET", "POST"])
@login_required
def protagonista():
    form = ProtagonistaForm()
    if form.validate_on_submit():

        if local_session.query(Protagonista).filter_by(name=form.name.data).first():
            
            #Protagonista already exists
            flash("Protagonista já cadastrado!")
            return redirect(url_for('protagonista'))

        new_protagonista = Protagonista(
            name=form.name.data,
        )
        local_session.add(new_protagonista)

        try:
            local_session.commit()
            flash("Adicionado com sucesso!")
        except:
            flash("Impossivel adicionar. Tente Novamente!")

        return redirect(url_for("protagonista_admin"))

    return render_template("protagonista.html", form=form, current_user=current_user)


@app.route('/protagonista-admin')
@login_required
def protagonista_admin():
    protagonistas = local_session.query(Protagonista).all()
    return render_template("protagonista_admin.html", current_user=current_user, protagonistas=protagonistas)


@app.route("/edit-protagonista/<int:protagonista_id>", methods=["GET", "POST"])
def edit_protagonista(protagonista_id):
    protagonista = local_session.query(Protagonista).get(protagonista_id)
    edit_protagonista = ProtagonistaForm(
        name=protagonista.name
    )

    if edit_protagonista.validate_on_submit():
        protagonista.name = edit_protagonista.name.data
        try:
            local_session.commit()
            flash("Modificado com sucesso!")
        except:
            flash("Impossivel modificar. Tente Novamente!")

        return redirect(url_for("protagonista_admin", protagonista_id=protagonista.id))

    return render_template("protagonista.html", form=edit_protagonista, is_edit=True)


@app.route("/delete-protagonista/<int:protagonista_id>")
@login_required
def delete_protagonista(protagonista_id):
    protagonista_to_delete = local_session.query(Protagonista).get(protagonista_id)
    local_session.delete(protagonista_to_delete)
    try:
        local_session.commit()
        flash("Deletado com sucesso!")
    except:
        flash("Impossivel deletar. Tente Novamente!")

    return redirect(url_for('protagonista_admin'))


###### Suporte #####
@app.route("/suporte", methods=["GET", "POST"])
@login_required
def suporte():
    form = SuporteForm()
    if form.validate_on_submit():

        if local_session.query(Suporte).filter_by(name=form.name.data).first():
            
            #Suporte already exists
            flash("Suporte já cadastrado!")
            return redirect(url_for('suporte'))

        new_suporte = Suporte(
            name=form.name.data,
        )
        local_session.add(new_suporte)

        try:
            local_session.commit()
            flash("Adicionado com sucesso!")
        except:
            flash("Impossivel adicionar. Tente Novamente!")

        return redirect(url_for("suporte_admin"))

    return render_template("suporte.html", form=form, current_user=current_user)


@app.route('/suporte-admin')
@login_required
def suporte_admin():
    suportes = local_session.query(Suporte).all()
    return render_template("suporte_admin.html", current_user=current_user, suportes=suportes)

@app.route("/edit-suporte/<int:suporte_id>", methods=["GET", "POST"])
def edit_suporte(suporte_id):
    suporte = local_session.query(Suporte).get(suporte_id)
    edit_suporte = SuporteForm(
        name=suporte.name
    )

    if edit_suporte.validate_on_submit():
        suporte.name = edit_suporte.name.data
        try:
            local_session.commit()
            flash("Modificado com sucesso!")
        except:
            flash("Impossivel modificar. Tente Novamente!")

        return redirect(url_for("suporte_admin", suporte_id=suporte.id))

    return render_template("suporte.html", form=edit_suporte, is_edit=True)


@app.route("/delete-suporte/<int:suporte_id>")
@login_required
def delete_suporte(suporte_id):
    suporte_to_delete = local_session.query(Suporte).get(suporte_id)
    local_session.delete(suporte_to_delete)
    try:
        local_session.commit()
        flash("Deletado com sucesso!")
    except:
        flash("Impossivel deletar. Tente Novamente!")

    return redirect(url_for('suporte_admin'))


###### Acervo #######
@app.route("/acervo", methods=["GET", "POST"])
@login_required
def acervo():
    form = AcervoForm()
    # Carrega as opçoes de midia
    form.midia.choices = [(midia.id, midia.name) for midia in local_session.query(Midia).all()]

    # Carrega as opçoes de suporte
    form.suporte.choices = [(suporte.id, suporte.name) for suporte in local_session.query(Suporte).all()]

    # Carrega as opções dos protagonistas
    form.protagonistas.choices = [(protagonista.id, protagonista.name) for protagonista in local_session.query(Protagonista).all()]

    if form.validate_on_submit():
        
        new_acervo = Acervo(
            name=form.evento.data,
            localidade=form.localidade.data,
            cidade=form.cidade.data,
            estado=form.estado.data,
            data_created=form.data_created.data,
            origem=form.original.data,
            autor_id=current_user.id,
            tipo_id=form.midia.data,
            suporte_id=form.suporte.data,
        )

        for protagonista in form.protagonistas.data:
            protagonista_obj = local_session.query(Protagonista).get(protagonista)
            new_acervo.protagonistas.append(protagonista_obj)


        local_session.add(new_acervo)

        try:
            local_session.commit()
            flash("Adicionado com sucesso!")
        except:
            flash("Impossivel adicionar. Tente Novamente!")

        return redirect(url_for("acervo_admin"))

    return render_template("acervo.html", form=form, current_user=current_user)


@app.route('/acervo-admin')
@login_required
def acervo_admin():
    eventos = local_session.query(Acervo).all()
    return render_template("acervo_admin.html", current_user=current_user, eventos=eventos)


@app.route("/edit-acervo/<int:acervo_id>", methods=["GET", "POST"])
def edit_acervo(acervo_id):

    acervo = local_session.query(Acervo).get(acervo_id)
    

    edit_acervo = AcervoForm(
        evento=acervo.name,
        localidade=acervo.localidade,
        cidade=acervo.cidade,
        estado=acervo.estado,
        original=acervo.origem,
        data_created = datetime.strptime(acervo.data_created, "%Y-%m-%d"),
        midia = acervo.tipo_id,
        suporte = acervo.suporte_id

    )
   
    # Carrega as opçoes de midia
    edit_acervo.midia.choices = [(midia.id, midia.name) for midia in local_session.query(Midia).all()]
    
    # Carrega as opçoes de suporte
    edit_acervo.suporte.choices = [(suporte.id, suporte.name) for suporte in local_session.query(Suporte).all()]

    edit_acervo.protagonistas.choices = [(protagonista.id, protagonista.name) for protagonista in local_session.query(Protagonista).all()]
     

    if edit_acervo.validate_on_submit():
        acervo.name = edit_acervo.evento.data
        acervo.localidade = edit_acervo.localidade.data
        acervo.cidade = edit_acervo.cidade.data
        acervo.estado = edit_acervo.estado.data
        acervo.tipo_id = edit_acervo.midia.data
        acervo.origem = edit_acervo.original.data
        acervo.suporte_id = edit_acervo.suporte.data
        acervo.data_created = edit_acervo.data_created.data.strftime("%Y-%m-%d")

        
        for protagonista in local_session.query(Protagonista).all():
            if protagonista in acervo.protagonistas:
                acervo.protagonistas.remove(protagonista)
        

        for protagonista in edit_acervo.protagonistas.data:
            protagonista_obj = local_session.query(Protagonista).get(protagonista)
            acervo.protagonistas.append(protagonista_obj)

        
        try:
            local_session.commit()
            flash("Modificado com sucesso!")
        except:
            flash("Impossivel modificar. Tente Novamente!")

        return redirect(url_for("acervo_admin", acervo_id=acervo.id))

    return render_template("acervo.html", form=edit_acervo, is_edit=True)


@app.route("/delete-acervo/<int:acervo_id>")
@login_required
def delete_acervo(acervo_id):
    acervo_to_delete = local_session.query(Acervo).get(acervo_id)
    local_session.delete(acervo_to_delete)
    try:
        local_session.commit()
        flash("Deletado com sucesso!")
    except:
        flash("Impossivel deletar. Tente Novamente!")

    return redirect(url_for('acervo_admin'))


@app.route("/search", methods=["GET", "POST"])
def search():

    search_form = SearchForm()
   
    query = local_session.query(Acervo).all()
       
    if search_form.validate_on_submit():

        if search_form.order_by.data == 1:  
            query = local_session.query(Acervo).filter(Acervo.name.like(f'%{search_form.search.data}%')).all()
        elif search_form.order_by.data == 2:  
            query = local_session.query(Acervo).filter(Acervo.data_created.like(f'%{search_form.search.data}%')).order_by(Acervo.data_created).all()
        elif search_form.order_by.data == 3:  
            query = local_session.query(Acervo).filter(Acervo.localidade.like(f'%{search_form.search.data}%')).order_by(Acervo.localidade).all()
        elif search_form.order_by.data == 4:  
            query = local_session.query(Acervo).filter(Acervo.protagonistas.any(Protagonista.name.like(f'%{search_form.search.data}%'))).all()      
        
        return render_template("search.html", form=search_form, search=query, type=search_form.order_by.data)  

    return render_template("search.html", form=search_form, search=query)   


@app.route("/search/<int:search_id>", methods=["GET", "POST"])
def search_nav(search_id):

    search_form = SearchForm()
   
    if search_id == 1:
        query = local_session.query(Acervo).order_by(Acervo.name).all()
    elif search_id == 2:
        query = local_session.query(Acervo).order_by(Acervo.data_created).all()
    elif search_id == 3:
        query = local_session.query(Acervo).filter(Acervo.protagonistas.any(Protagonista.name.like("%Anto%"))).all()
    elif search_id == 4:
        query = local_session.query(Acervo).order_by(Acervo.localidade).all()
    elif search_id == 5:
        query = local_session.query(Acervo).filter(Acervo.tipo.has(Midia.name=="Livro")).all()
    elif search_id == 6:
        query = local_session.query(Acervo).filter(Acervo.tipo.has(Midia.name.like("%Li%"))).all()


    if search_form.validate_on_submit():

        if search_form.order_by.data == 1:  
            query = local_session.query(Acervo).filter(Acervo.name.like(f'%{search_form.search.data}%')).all()
        elif search_form.order_by.data == 2:  
            query = local_session.query(Acervo).filter(Acervo.data_created.like(f'%{search_form.search.data}%')).order_by(Acervo.data_created).all()
        elif search_form.order_by.data == 3:  
            query = local_session.query(Acervo).filter(Acervo.localidade.like(f'%{search_form.search.data}%')).order_by(Acervo.localidade).all()
        elif search_form.order_by.data == 4:  
            query = local_session.query(Acervo).filter(Acervo.protagonistas.any(Protagonista.name.like(f'%{search_form.search.data}%'))).all()  
        
        return render_template("search.html", form=search_form, search=query, type=search_form.order_by.data)

    return render_template("search.html", form=search_form, search=query)  


@app.route("/view-item/<int:item_id>", methods=["GET", "POST"])
def view_item(item_id):
    query = local_session.query(Acervo).filter(Acervo.id == item_id).first()

    return render_template("view_item.html", search=query)  


# Invalid URL
@app.errorhandler(404)
def page_not_find(e):
    return render_template("404.html"), 404

if __name__ == "__main__":
    app.run(debug=True)
