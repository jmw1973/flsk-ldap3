from flask_wtf import FlaskForm, RecaptchaField
from wtforms import (
            DateField,
            PasswordField,
            SelectField,
            StringField,
            SubmitField,
            TextAreaField,
)
from wtforms.validators import URL, DataRequired, Email, EqualTo, Length

class SignupForm(FlaskForm):
  """Sign up for a user account."""

  logonname = StringField("Logon Name")
  #password = PasswordField("Password", [DataRequired(message="Please enter a password.")],)
  #confirmPassword = PasswordField("Repeat Password", [EqualTo(password, message="Passwords must match.")])
  tenant = SelectField(
          "Tenant",
          [DataRequired()],
          choices=[
               ("Pit1", "pit1"),
               ("Tenanttest1", "tenanttest1"),
               ("Tenanttest2", "tenanttest2"),
                                                                                                                                  ],
                                                            )
  otherinfo = StringField("Other Info")
  submit = SubmitField("Submit")
