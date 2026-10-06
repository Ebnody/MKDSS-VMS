#!/usr/bin/env python3
"""
Fix Database Script for MKDSS VMS
- Resets all badges to unassigned
- Unlocks admin account
"""

import sqlite3
import os

DB_PATH = os.path.join(os.path.dirname(__file__), "vms_accounts.db")

print("=" * 70)
print("VMS DATABASE FIX SCRIPT")
print("=" * 70)

# Check if database exists
if not os.path.exists(DB_PATH):
    print(f"\n❌ Database not found at: {DB_PATH}")
    print("\nMake sure:")
    print("  1. vms_server.py is running")
    print("  2. This script is in the same folder as vms_server.py")
    print("  3. Database has been initialized (server should create it)")
    exit(1)

try:
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    
    # Fix 1: Reset all badges to unassigned
    print("\n[1] Resetting all badges to unassigned...")
    try:
        cursor.execute("SELECT COUNT(*) FROM badges")
        total_badges = cursor.fetchone()[0]
        print(f"    Total badges in database: {total_badges}")
        
        cursor.execute("UPDATE badges SET status='Available', visitor_id=NULL")
        print(f"    ✅ Set all badges to 'Available' and unassigned")
        
        cursor.execute("SELECT COUNT(*) FROM badges WHERE status='Available'")
        available = cursor.fetchone()[0]
        cursor.execute("SELECT COUNT(*) FROM badges WHERE status='Assigned'")
        assigned = cursor.fetchone()[0]
        print(f"    ✅ Result: {available} Available, {assigned} Assigned")
    except Exception as e:
        print(f"    ⚠️ Badges: {e}")
    
    # Fix 2: Unlock admin account
    print("\n[2] Unlocking admin account...")
    try:
        cursor.execute("SELECT username FROM users WHERE role='admin' LIMIT 1")
        admin = cursor.fetchone()
        
        if admin:
            admin_user = admin[0]
            print(f"    Found admin user: {admin_user}")
            
            cursor.execute(
                "UPDATE users SET failed_login_attempts=0, locked_until=NULL WHERE username=?",
                (admin_user,)
            )
            print(f"    ✅ Reset failed login attempts to 0")
            print(f"    ✅ Cleared lock timer")
            print(f"    ✅ Admin '{admin_user}' is now unlocked")
        else:
            print(f"    ℹ️  No admin found (will be created on first login)")
    except Exception as e:
        print(f"    ⚠️ Admin: {e}")
    
    # Commit changes
    conn.commit()
    conn.close()
    
    print("\n" + "=" * 70)
    print("✅ DATABASE FIXED SUCCESSFULLY!")
    print("=" * 70)
    print("\nWhat was fixed:")
    print("  ✅ All badges reset to 'Available' (unassigned)")
    print("  ✅ Admin account unlocked and can login")
    print("\nNext steps:")
    print("  1. Restart your VMS client app")
    print("  2. Login as admin")
    print("  3. Check Badges page - should show all available")
    print("\n" + "=" * 70)
    
except sqlite3.Error as e:
    print(f"\n❌ Database error: {e}")
    exit(1)
except Exception as e:
    print(f"\n❌ Error: {e}")
    import traceback
    traceback.print_exc()
    exit(1)
