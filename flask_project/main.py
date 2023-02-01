import sys
from sqlalchemy.orm import Session
from sqlalchemy import create_engine
from models import Role, User, IP_address, Domains


def main():
    
    # temporary credentials
    password = "secret"
    user = "username"
    database = "database"
    host = "192.168.1.33"
    port = "5432"
    
    engine = create_engine("postgresql://username:secret@192.168.1.33:5432/database")
    session = Session(engine)

    new_role = Role(role_id= 11, role_name="rn", role_description="rd")
    
    session.add(new_role)
    session.commit()


if __name__ == "__main__":
    sys.exit(main())
