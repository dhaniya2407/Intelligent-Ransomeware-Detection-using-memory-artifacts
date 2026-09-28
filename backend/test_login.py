from getpass import getpass
from database import SessionLocal
from models import User
from passlib.context import CryptContext

pwd_context = CryptContext(
    schemes=["bcrypt"],
    deprecated="auto"
)

db = SessionLocal()

try:
    print("\nRegistered users:")
    users = db.query(User).all()

    if not users:
        print("No users found in the database.")

    for user in users:
        print(f"- Username: {user.username}")
        print(f"  Email: {user.email}")
        print(f"  Hash prefix: {user.password_hash[:7]}")
        print()

    username = input("Enter your registered username: ").strip()
    password = getpass("Enter your password: ")

    user = db.query(User).filter(
        User.username == username
    ).first()

    if not user:
        print("\nRESULT: USER NOT FOUND")
    else:
        print(f"\nUser found: {user.username}")
        print(f"Hash length: {len(user.password_hash)}")

        try:
            is_valid = pwd_context.verify(
                password,
                user.password_hash
            )

            if is_valid:
                print("RESULT: PASSWORD VERIFIED")
            else:
                print("RESULT: PASSWORD DOES NOT MATCH")

        except Exception as error:
            print("RESULT: PASSWORD VERIFICATION ERROR")
            print(type(error).__name__)
            print(str(error))

finally:
    db.close()