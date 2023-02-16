

# ScanSafe App

version 1.0

ScanSafe App is a free app that allows you to quickly and easily check if a website link is safe to visit. With just one tap, you can scan any URL to see if it contains any known malware, phising scams, spamming or other harmful content.

ScanSafe App uses its own resources and technology provided by IPQualityScore service, thanks to that you will be safe while browsing the internet.

Features:

* Quick and easily URL scanning
* Web security technology
* Real-time detection of malware and phising scams
* Free to use!

<center><b>Stay safe with the <span style="color:red;">ScanSafe</span> app!</b></center>



## Version 1.0

- [x] Scan URL via IP Quality Score service and store scan results in DB
- [ ] Get all phishing URLs/domains. <span style="color:red;">In progress, CR</span>
- [ ] Get all malware URLs/domains. <span style="color:red;">In progress, CR</span>
- [ ] Get all spamming URLs/domains. <span style="color:red;">In progress, CR</span>
- [ ] Takes some text and checks if some threat URLs present in it.
- [ ] Get specified URL or list of URLs scan info.
- [ ] Get specified URL or list of domains scan info.
- [ ] Scrap sub-URLs from homepage for given domain.

# Some examples

![image-20230216133038611](C:\Users\Kamil\AppData\Roaming\Typora\typora-user-images\image-20230216133038611.png)



# For contributors:

## Before work

Before making changes to the code always execute `git pull` command to download latest version, and create new branch for your work.

```
git pull
git checkout -b branch-name
```

## How to run it?

### Environmental  Variables

Create .env file and copy below content, between ' ' paste your own data.

```
IPQS_SECRET_KEY='yours_ipqs_secret_key'
DB_CONTAINER_NAME=''
POSTGRES_USER=''
POSTGRES_PASSWORD=''
POSTGRES_DB=''
POSTGRES_PORT=''
DATABASE_URL="postgresql://${POSTGRES_USER}:${POSTGRES_PASSWORD}@postgresql_container:5432/${POSTGRES_DB}"
```

### Docker

```bash
docker-compose up -d --build # for the first time
docker-compose up -d # when image is built
```

### Virtual Environment

Create virtual environment

```
python3 -m venv .venv # ".venv" is only example of yours virtual environment name
source ./venv/bin/activate
pip install -r requirements.txt
```

After installing new module

```bash
pip freeze > requirements.txt
```

### Database initialization

When you run project for the first time, please open shell in flask_app container and run

```
flask --app flask_project shell
db.create_all()
```

### Browser

Open `http://127.0.0.1:5000/` in your browser or use tools like Postman.
