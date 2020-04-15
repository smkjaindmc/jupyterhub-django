# jupyterhub-django
Makes use of Django allauth to launch jupyterhub from django authentication system. Here django is service provider and Jupyterhub is client application. OAuth or open authentication is used. Two servers are used. One is the python server to launch django and another one for JupyterHub. To launch jupyterhub, shell script is executed on windows using wsl. Both the servers run simultaneously.y

# Install

Move on to command prompt and type: - 

pip install django  (for django)

pip install django-oauth-toolkit==1.2.0 (for oauth)

pip install django-cors-middleware==1.4.0 (for cors - cross origin resource shairing)

pip install jupyter==1.0.0 jupyterhub==1.0.0 oauthenticator==0.9.0 (for jupyter, jupyterhub, oauthenticator)

# Running servers

Move to django project folder and launch cmd:-

python manage.py runserver

Move to folder containing script file:-

For windows type:-
bash filename.sh

For ubuntu:-
chmod u+x filename.sh
./filename.sh

