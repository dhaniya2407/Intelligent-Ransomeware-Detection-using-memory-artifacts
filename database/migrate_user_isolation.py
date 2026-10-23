"""
ForensiRansom AI - User Isolation Database Migration
Adds user_id foreign key to cases and associates existing records safely with verified owner.
"""

import os
import sys
import sqlite3
import shutil

PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DB_PATH = os.path.join(PROJECT_ROOT, "forensic.db")

def run_migration(db_path: str = DB_PATH, dry_run: bool = False):
    print(f"[*] Running database migration on: {db_path}")
    if not os.path.exists(db_path):
        raise FileNotFoundError(f"Database file not found: {db_path}")

    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()

    try:
        # 1. Inspect existing columns in cases
        cursor.execute("PRAGMA table_info(cases);")
        columns = [row[1] for row in cursor.fetchall()]
        print(f"[*] Current columns in 'cases': {columns}")

        if "user_id" not in columns:
            print("[+] Adding 'user_id' column to 'cases' table...")
            if not dry_run:
                cursor.execute("ALTER TABLE cases ADD COLUMN user_id INTEGER REFERENCES users(id);")
                conn.commit()
            print("[+] 'user_id' column added.")
        else:
            print("[*] 'user_id' column already exists in 'cases'.")

        # 2. Inspect users
        cursor.execute("SELECT id, username, email FROM users WHERE LOWER(username) = 'dhaniya';")
        owner_user = cursor.fetchone()
        if not owner_user:
            print("[!] Warning: User 'dhaniya' not found. Checking all users...")
            cursor.execute("SELECT id, username, email FROM users;")
            all_users = cursor.fetchall()
            print(f"[*] Available users: {all_users}")
            owner_id = all_users[0][0] if all_users else None
        else:
            owner_id = owner_user[0]
            print(f"[+] Found legitimate owner user 'dhaniya' with ID: {owner_id}")

        if owner_id is not None:
            # 3. Associate cases where investigator matches Dhaniya
            cursor.execute("""
                SELECT id, case_id, investigator, user_id FROM cases
                WHERE user_id IS NULL OR user_id = 0;
            """)
            unassigned_cases = cursor.fetchall()
            print(f"[*] Found {len(unassigned_cases)} unassigned case(s): {unassigned_cases}")

            assigned_count = 0
            for cid, case_id, investigator, uid in unassigned_cases:
                inv_lower = (investigator or "").lower()
                if "dhaniya" in inv_lower:
                    if not dry_run:
                        cursor.execute("UPDATE cases SET user_id = ? WHERE id = ?;", (owner_id, cid))
                    assigned_count += 1
                    print(f"[+] Assigned case {case_id} (Investigator: '{investigator}') to user_id {owner_id}")
                else:
                    print(f"[?] Case {case_id} investigator '{investigator}' does not match Dhaniya. Leaving unassigned for review.")

            if not dry_run:
                conn.commit()
            print(f"[+] Successfully migrated {assigned_count} case(s) to user_id {owner_id}.")

        # 4. Final verification
        cursor.execute("SELECT id, case_id, case_name, investigator, user_id FROM cases;")
        final_cases = cursor.fetchall()
        print("[*] Cases after migration:")
        for fc in final_cases:
            print(f"    - {fc}")

        return True
    finally:
        conn.close()

if __name__ == "__main__":
    is_dry = "--dry-run" in sys.argv
    run_migration(dry_run=is_dry)
