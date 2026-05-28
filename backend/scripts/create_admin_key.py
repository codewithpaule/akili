#!/usr/bin/env python3
"""Utility: create a permanent admin API key for the admin user.

Usage:
  python backend/scripts/create_admin_key.py --email admin@example.com --name "Admin permanent key"

If --email is omitted, the script will try the ADMIN_EMAIL from .env.
"""
import argparse
import os
import sys
import time
from dotenv import load_dotenv
load_dotenv()

# Ensure backend package modules are importable when running from scripts/
ROOT = os.path.dirname(os.path.dirname(__file__))
if ROOT not in sys.path:
    sys.path.insert(0, ROOT)

from database import get_db, User
from api_keys import generate_permanent_admin_key


def find_admin_by_email(email: str):
    with get_db() as db:
        row = db.query(User).filter(User.email == email, User.is_active == True).first()
        if not row:
            return None
        return {"user_id": row.user_id, "email": row.email, "role": getattr(row, "role", "user")}


def find_any_admin():
    with get_db() as db:
        row = db.query(User).filter(User.role == 'admin', User.is_active == True).order_by(User.created_at.asc()).first()
        if not row:
            return None
        return {"user_id": row.user_id, "email": row.email, "role": getattr(row, "role", "admin")}


def main():
    p = argparse.ArgumentParser()
    p.add_argument('--email', help='Admin email to create key for')
    p.add_argument('--name', help='Key name label', default='Permanent admin key')
    args = p.parse_args()

    email = (args.email or os.getenv('ADMIN_EMAIL') or '').strip().lower()
    if email:
        row = find_admin_by_email(email)
        if not row:
            print('Admin user not found for email:', email)
            sys.exit(2)
    else:
        row = find_any_admin()
        if not row:
            print('No admin user found in database; set ADMIN_EMAIL in .env and run bootstrap or create an admin first')
            sys.exit(2)

    user_dict = {
        'user_id': row['user_id'],
        'email': row['email'],
        'role': row.get('role', 'admin'),
        'is_admin': True,
    }

    out = generate_permanent_admin_key(user_dict['user_id'], user_dict, name=args.name)
    print('Created permanent admin API key:')
    print(out['api_key'])
    print('\nPreview:', out['preview'])
    print('\nSave this key securely; it will not be displayed again.')


if __name__ == '__main__':
    main()
