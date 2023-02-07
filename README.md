# Before work

Before making changes to the code always execute `git pull` command to download latest version.

```
git pull
```

# During the work

After installing new module

```bash
pip freeze > requirements.txt
```

# How to run it

Download repository from github

* Create virtual environment and install all requirements.

```bash
python3 -m venv .venv # ".venv" is only example of yours virtual environment name
source .venv/bin/activate
pip install -r requirements.txt
```

* To run Flask App and DB

```bash
docker-compose up -d
```

Visit 127.0.0.1:5000 in your browser.

# .ENV

```bash
IPQS_SECRET_KEY='yours_ipqs_secret_key'
DB_CONTAINER_NAME=''
POSTGRES_USER=''
POSTGRES_PASSWORD=''
POSTGRES_DB=''
POSTGRES_PORT=''
DATABASE_URL="postgresql://${POSTGRES_USER}:${POSTGRES_PASSWORD}@postgresql_container:5432/${POSTGRES_DB}"
```

# Database initialization

Open shell in flask_app container and run

```
flask --app flask_project shell
db.create_all()
```

