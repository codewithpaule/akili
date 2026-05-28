#!/usr/bin/env python3
"""Promote an existing user to admin by email.

Usage:
  python backend/scripts/promote_admin.py --email you@example.com

This script updates the `users` table to set `role='admin'` and `is_active=True`.
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


def promote_by_email(email: str) -> None:
    email = (email or "").strip().lower()
    if not email:
        print('Provide an email with --email')
        sys.exit(2)
    with get_db() as db:
        row = db.query(User).filter(User.email == email).first()
        if not row:
            print('User not found for email:', email)
            sys.exit(2)
        row.role = 'admin'
        row.is_active = True
        row.updated_at = int(time.time())
    print('Promoted user to admin:', email)


def main():
    p = argparse.ArgumentParser()
    p.add_argument('--email', required=True, help='Email address of user to promote')
    args = p.parse_args()
    promote_by_email(args.email)


if __name__ == '__main__':
    main()
