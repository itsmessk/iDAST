import asyncio
import secrets
import json
from datetime import datetime, timedelta
from motor.motor_asyncio import AsyncIOMotorClient
from typing import List, Dict
import os
from dotenv import load_dotenv
import certifi

# Load environment variables
load_dotenv()

# MongoDB configuration
MONGO_URI = os.getenv('MONGO_URI', 'mongodb+srv://secpro_user:your_password@your_cluster.mongodb.net/?retryWrites=true&w=majority')
MONGO_DB_NAME = os.getenv('MONGO_DB_NAME', 'secpro')
MONGO_USER_COLLECTION = os.getenv('MONGO_USER_COLLECTION', 'users')

# MongoDB connection options
MONGO_OPTIONS = {
    'tlsCAFile': certifi.where(),
    'retryWrites': True,
    'w': 'majority'
}

def create_target_id(domain: str, name: str) -> Dict:
    """Create a target ID with metadata for a specific site."""
    timestamp = datetime.now().strftime('%Y%m%d%H%M%S')
    random_suffix = secrets.token_hex(4)
    target_id = f"target_{domain}_{timestamp}_{random_suffix}"
    
    return {
        "id": target_id,
        "domain": domain,
        "name": name,
        "created_at": datetime.utcnow(),
        "status": "active",
        "scan_frequency": "daily",
        "last_scan": None,
        "risk_level": "high" if domain == "infoziant.com" else "medium",
        "tags": ["test", f"domain-{domain}"],
        "metadata": {
            "created_by": "manual",
            "environment": "production" if domain == "infoziant.com" else "testing"
        }
    }

def generate_api_key_details() -> Dict:
    """Generate API key details with expiration."""
    return {
        "key": f"secpro_{secrets.token_hex(16)}",
        "created_at": datetime.utcnow(),
        "expires_at": datetime.utcnow() + timedelta(days=30),
        "status": "active",
        "last_renewed": None,
        "metadata": {
            "created_by": "manual",
            "environment": "production"
        }
    }

async def create_user(email: str, name: str, company: str, domains: List[Dict[str, str]]):
    """Create a user with specific targets in MongoDB."""
    try:
        # Connect to MongoDB Atlas
        client = AsyncIOMotorClient(MONGO_URI, **MONGO_OPTIONS)
        db = client[MONGO_DB_NAME]
        users_collection = db[MONGO_USER_COLLECTION]

        # Generate API key details
        api_key_details = generate_api_key_details()
        
        # Generate targets for specified domains
        targets = [create_target_id(domain['domain'], domain['name']) for domain in domains]
        
        # Create user data
        user_data = {
            "email": email,
            "name": name,
            "username": f"user_{secrets.token_hex(4)}",
            "api_key": api_key_details["key"],
            "api_key_details": api_key_details,
            "role": "admin",
            "status": "active",
            "created_at": datetime.utcnow(),
            "last_login": None,
            "company": company,
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
                "source": "manual_creation",
                "environment": "production"
            }
        }

        # Insert user into database
        result = await users_collection.insert_one(user_data)
        
        # Print success message and user details
        print("\n=== User Created Successfully ===")
        print(f"User ID: {result.inserted_id}")
        print(f"Username: {user_data['username']}")
        print(f"Email: {user_data['email']}")
        print("\nAPI Key Details:")
        print(f"Key: {api_key_details['key']}")
        print(f"Created: {api_key_details['created_at'].strftime('%Y-%m-%d %H:%M:%S')}")
        print(f"Expires: {api_key_details['expires_at'].strftime('%Y-%m-%d %H:%M:%S')}")
        print(f"Status: {api_key_details['status']}")
        
        print("\nTarget IDs:")
        for target in targets:
            print(f"- {target['id']}")
            print(f"  Domain: {target['domain']}")
            print(f"  Name: {target['name']}")
            print(f"  Risk Level: {target['risk_level']}")
            print()
        
        print("\n=== Example API Request ===")
        print("curl -X POST http://localhost:3000/scan \\")
        print("-H 'Content-Type: application/json' \\")
        print(f"-H 'X-API-Key: {api_key_details['key']}' \\")
        print("-d '{")
        print(f'  "targetid": "{targets[0]["id"]}"')
        print("}'")

        # Close MongoDB connection
        client.close()

    except Exception as e:
        print(f"Error creating user: {e}")

if __name__ == "__main__":
    # Example usage
    test_domains = [
        {"domain": "infoziant.com", "name": "Infoziant Production"},
        {"domain": "staging.infoziant.com", "name": "Infoziant Staging"},
        {"domain": "dev.infoziant.com", "name": "Infoziant Development"}
    ]
    
    asyncio.run(create_user(
        email="security@infoziant.com",
        name="Security Team",
        company="Infoziant",
        domains=test_domains
    ))