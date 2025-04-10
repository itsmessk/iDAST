import asyncio
import secrets
import json
from datetime import datetime, timedelta
from motor.motor_asyncio import AsyncIOMotorClient
from typing import List, Dict
import os
from dotenv import load_dotenv

# Load environment variables
load_dotenv()

import certifi

# MongoDB configuration
MONGO_URI = os.getenv('MONGO_URI', 'mongodb+srv://secpro_user:drbgQZAeFdTEK06j@secpro.vexiur2.mongodb.net/?retryWrites=true&w=majority&appName=secpro')
MONGO_DB_NAME = os.getenv('MONGO_DB_NAME', 'secpro')
MONGO_USER_COLLECTION = os.getenv('MONGO_USER_COLLECTION', 'users')

# MongoDB connection options
MONGO_OPTIONS = {
    'tlsCAFile': certifi.where(),
    'retryWrites': True,
    'w': 'majority'
}

def generate_api_key() -> Dict:
    """Generate a secure API key with expiration."""
    return {
        "key": f"secpro_{secrets.token_hex(16)}",
        "created_at": datetime.utcnow(),
        "expires_at": datetime.utcnow() + timedelta(days=30),  # 30 days validity
        "status": "active",
        "last_renewed": None
    }

def generate_target_ids() -> List[Dict]:
    """Generate target IDs with metadata for specific sites."""
    sites = [
        {"domain": "infoziant.com", "name": "Infoziant", "risk_level": "high"},
        {"domain": "example.com", "name": "Example Site", "risk_level": "medium"},
        {"domain": "testsite.local", "name": "Test Environment", "risk_level": "low"}
    ]
    
    targets = []
    timestamp = datetime.now().strftime('%Y%m%d%H%M%S')
    
    for site in sites:
        random_suffix = secrets.token_hex(4)
        target_id = f"target_{site['domain']}_{timestamp}_{random_suffix}"
        targets.append({
            "id": target_id,
            "domain": site['domain'],
            "name": site['name'],
            "created_at": datetime.utcnow(),
            "status": "active",
            "scan_frequency": "daily",
            "last_scan": None,
            "risk_level": site['risk_level'],
            "tags": ["test", f"domain-{site['domain']}"]
        })
    return targets

async def create_test_user():
    """Create a test user with complete profile in MongoDB."""
    try:
        # Connect to MongoDB Atlas
        client = AsyncIOMotorClient(MONGO_URI, **MONGO_OPTIONS)
        db = client[MONGO_DB_NAME]
        users_collection = db[MONGO_USER_COLLECTION]

        # Generate user data
        api_key_data = generate_api_key()
        targets = generate_target_ids()
        
        user_data = {
            "email": "test@secpro.local",
            "name": "Test User",
            "username": f"testuser_{secrets.token_hex(4)}",
            "api_key": api_key_data["key"],
            "api_key_details": api_key_data,
            "role": "admin",
            "status": "active",
            "created_at": datetime.utcnow(),
            "last_login": None,
            "company": "SecPro Testing",
            "department": "Security",
            "phone": "+1234567890",
            "targets": targets,
            "preferences": {
                "notification_email": True,
                "notification_slack": False,
                "scan_schedule": "daily",
                "report_format": "pdf",
                "timezone": "UTC"
            },
            "limits": {
                "max_scans_per_day": 100,
                "max_concurrent_scans": 5,
                "max_targets": 50
            },
            "metadata": {
                "source": "test_script",
                "environment": "testing"
            }
        }

        # Insert user into database
        result = await users_collection.insert_one(user_data)
        
        # Print success message and user details
        print("\n=== Test User Created Successfully ===")
        print(f"User ID: {result.inserted_id}")
        print(f"Username: {user_data['username']}")
        print(f"Email: {user_data['email']}")
        print(f"API Key: {api_key_data['key']}")
        print(f"API Key Expires: {api_key_data['expires_at'].strftime('%Y-%m-%d %H:%M:%S UTC')}")
        print("\nTarget IDs:")
        for target in targets:
            print(f"- {target['id']} ({target['name']})")
        
        print("\n=== Example API Request ===")
        print("curl -X POST http://localhost:3000/scan \\")
        print("-H 'Content-Type: application/json' \\")
        print(f"-H 'X-API-Key: {api_key}' \\")
        print("-d '{")
        print(f'  "domain": "example.com",')
        print('  "scan_type": "quick",')
        print(f'  "targetid": "{targets[0]["id"]}"')
        print("}'")

        # Close MongoDB connection
        client.close()

    except Exception as e:
        print(f"Error creating test user: {e}")

if __name__ == "__main__":
    asyncio.run(create_test_user())