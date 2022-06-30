from flask_wtf import FlaskForm
from wtforms import StringField, SubmitField, PasswordField, EmailField, SelectField, DateField, validators, SelectMultipleField
from wtforms.validators import DataRequired, Email


MENSAGEM_PADRAO = "Campo Obrigatório"


#form login sistema
class LoginForm(FlaskForm):
    email = StringField("Email", validators=[DataRequired(MENSAGEM_PADRAO)])
    password = PasswordField("Senha", validators=[DataRequired(MENSAGEM_PADRAO)])
    submit = SubmitField("Acessar")


#formulário cadastro usuario
class UsersForm(FlaskForm):
    fullname = StringField("Nome Completo", validators=[DataRequired(MENSAGEM_PADRAO)])
    email= EmailField("Email", validators=[Email(MENSAGEM_PADRAO)])
    password = PasswordField("Senha", [
        validators.DataRequired(MENSAGEM_PADRAO),
        validators.EqualTo('confirm', message='Senha deve repetir')])

    confirm = PasswordField('Digite a senha novamente')
    submit = SubmitField("Cadastrar")

#form cadastro Tipo midia
class MidiaForm(FlaskForm):
    name = StringField("Nome", validators=[DataRequired(MENSAGEM_PADRAO)])
    submit = SubmitField("Cadastrar")


#form cadastro Protagonista
class ProtagonistaForm(FlaskForm):
    name = StringField("Nome", validators=[DataRequired(MENSAGEM_PADRAO)])
    submit = SubmitField("Cadastrar")


#form cadastro Suporte
class SuporteForm(FlaskForm):
    name = StringField("Nome", validators=[DataRequired(MENSAGEM_PADRAO)])
    submit = SubmitField("Cadastrar")

#form cadastro acervo
class AcervoForm(FlaskForm):
    evento = StringField("Nome do Evento", validators=[DataRequired(MENSAGEM_PADRAO)])
    localidade = StringField("Localidade", validators=[DataRequired(MENSAGEM_PADRAO)])
    cidade = StringField("Cidade", validators=[DataRequired(MENSAGEM_PADRAO)])
    estado = StringField("Estado", validators=[DataRequired(MENSAGEM_PADRAO)])
    data_created = DateField("Data do evento", format="%Y-%m-%d")
    midia = SelectField("Selecione uma midia", validate_choice=True, choices=[], coerce=int)
    protagonistas = SelectMultipleField("Protagonistas", validate_choice=True, choices=[], coerce=int)
    original = StringField("Acervo Original", validators=[DataRequired(MENSAGEM_PADRAO)])
    suporte = SelectField("Selecione um suporte", validate_choice=True, choices=[], coerce=int)
    submit = SubmitField("Cadastrar")

#form busca
class SearchForm(FlaskForm):
    search = StringField("Busca no acervo", validators=[DataRequired(MENSAGEM_PADRAO)])
    order_by = SelectField("Buscar por: ", validate_choice=True, choices=[(1,"Evento"), (2, "Data do Evento"), (3, "Localidade"), (4, "Protagonistas")], coerce=int)
    asc_desc = SelectField("Na Ordem", validate_choice=True, choices=[(1,"Ascendente"), (2, "Descendente")], coerce=int)
    submit = SubmitField("Buscar")

