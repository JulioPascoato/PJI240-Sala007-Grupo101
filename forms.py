from flask_wtf import FlaskForm
from wtforms import StringField, SubmitField, PasswordField, EmailField
from wtforms.validators import DataRequired, URL, Email
from flask_ckeditor import CKEditorField


#form login sistema
class LoginForm(FlaskForm):
    email = StringField("Email", validators=[DataRequired()])
    password = PasswordField("Senha", validators=[DataRequired()])
    submit = SubmitField("Acessar")


#formulário cadastro usuario
class UsersForm(FlaskForm):
    fullname = StringField("Nome Completo", validators=[DataRequired()])
    email= EmailField("Email", validators=[Email()])
    password = PasswordField("Senha", validators=[DataRequired()])
    submit = SubmitField("Cadastrar")

#form cadastro Tipo midia
class MidiaForm(FlaskForm):
    name = StringField("Nome", validators=[DataRequired()])
    submit = SubmitField("Cadastrar")


#form cadastro Protagonista
class ProtagonistaForm(FlaskForm):
    name = StringField("Nome", validators=[DataRequired()])
    submit = SubmitField("Cadastrar")


#form cadastro Suporte
class SuporteForm(FlaskForm):
    name = StringField("Nome", validators=[DataRequired()])
    submit = SubmitField("Cadastrar")
    