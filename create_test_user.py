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
MONGO_TARGET_COLLECTION = os.getenv('MONGO_TARGET_COLLECTION', 'targets')

# MongoDB connection options
MONGO_OPTIONS = {
    'tlsCAFile': certifi.where(),
    'retryWrites': True,
    'w': 'majority'
}

# Scan configuration templates
SCAN_CONFIGS = {
    'production': {
        'quick': {
            'timeout': 300,
            'max_depth': 3,
            'excluded_paths': ['/admin', '/api'],
            'scan_types': ['sqlmap', 'xss', 'ssrf', 'csrf'],
            'concurrent_requests': 5,
            'retry_count': 3,
            'headers': {
                'User-Agent': 'SecPro Scanner/1.0'
            }
        },
        'full': {
            'timeout': 600,
            'max_depth': 5,
            'excluded_paths': ['/admin'],
            'scan_types': ['sqlmap', 'xss', 'ssrf', 'csrf', 'lfi', 'rce', 'xxe'],
            'concurrent_requests': 10,
            'retry_count': 5,
            'headers': {
                'User-Agent': 'SecPro Scanner/1.0'
            }
        }
    },
    'testing': {
        'quick': {
            'timeout': 180,
            'max_depth': 2,
            'excluded_paths': ['/admin', '/api', '/test'],
            'scan_types': ['sqlmap', 'xss'],
            'concurrent_requests': 3,
            'retry_count': 2,
            'headers': {
                'User-Agent': 'SecPro Scanner/1.0 (Testing)'
            }
        },
        'full': {
            'timeout': 300,
            'max_depth': 3,
            'excluded_paths': ['/admin'],
            'scan_types': ['sqlmap', 'xss', 'ssrf', 'csrf', 'lfi'],
            'concurrent_requests': 5,
            'retry_count': 3,
            'headers': {
                'User-Agent': 'SecPro Scanner/1.0 (Testing)'
            }
        }
    }
}

def create_target(domain: str, name: str, user_id: str, environment: str = 'production') -> Dict:
    """Create a target with scan configuration."""
    timestamp = datetime.now().strftime('%Y%m%d%H%M%S')
    random_suffix = secrets.token_hex(4)
    target_id = f"target_{domain}_{timestamp}_{random_suffix}"
    
    # Determine environment and risk level
    is_production = domain == "infoziant.com" or environment == "production"
    env = "production" if is_production else "testing"
    risk_level = "high" if is_production else "medium"
    
    return {
        "_id": target_id,
        "domain": domain,
        "name": name,
        "created_at": datetime.utcnow(),
        "status": "active",
        "scan_frequency": "daily",
        "last_scan": None,
        "risk_level": risk_level,
        "tags": ["test", f"domain-{domain}"],
        "user_id": user_id,  # Reference to user
        "scan_config": {
            "quick": SCAN_CONFIGS[env]['quick'],
            "full": SCAN_CONFIGS[env]['full'],
            "custom": {
                "timeout": 450,
                "max_depth": 4,
                "excluded_paths": ['/admin', '/api', '/test'],
                "scan_types": ['sqlmap', 'xss', 'ssrf'],
                "concurrent_requests": 7,
                "retry_count": 4,
                "headers": {
                    'User-Agent': f'SecPro Scanner/1.0 ({env.capitalize()})'
                }
            }
        },
        "metadata": {
            "created_by": "manual",
            "environment": env
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
        targets_collection = db[MONGO_TARGET_COLLECTION]

        # Generate API key details
        api_key_details = generate_api_key_details()
        
        # Create user first to get user_id
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
            "target_ids": [],  # Will store references to targets
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

        # Insert user and get user_id
        user_result = await users_collection.insert_one(user_data)
        user_id = str(user_result.inserted_id)

        # Create and insert targets
        target_ids = []
        for domain in domains:
            target_data = create_target(
                domain['domain'],
                domain['name'],
                user_id,
                domain.get('environment', 'production')
            )
            await targets_collection.insert_one(target_data)
            target_ids.append(target_data['_id'])

        # Update user with target references
        await users_collection.update_one(
            {"_id": user_result.inserted_id},
            {"$set": {"target_ids": target_ids}}
        )
        
        # Print success message and user details
        print("\n=== User Created Successfully ===")
        print(f"User ID: {user_result.inserted_id}")
        print(f"Username: {user_data['username']}")
        print(f"Email: {user_data['email']}")
        print("\nAPI Key Details:")
        print(f"Key: {api_key_details['key']}")
        print(f"Created: {api_key_details['created_at'].strftime('%Y-%m-%d %H:%M:%S')}")
        print(f"Expires: {api_key_details['expires_at'].strftime('%Y-%m-%d %H:%M:%S')}")
        print(f"Status: {api_key_details['status']}")
        
        print("\nTarget IDs:")
        for target_id in target_ids:
            target = await targets_collection.find_one({"_id": target_id})
            print(f"- {target['_id']}")
            print(f"  Domain: {target['domain']}")
            print(f"  Name: {target['name']}")
            print(f"  Risk Level: {target['risk_level']}")
            print(f"  Environment: {target['metadata']['environment']}")
            print()
        
        print("\n=== Example API Request ===")
        print("curl -X POST http://localhost:3000/scan \\")
        print("-H 'Content-Type: application/json' \\")
        print(f"-H 'X-API-Key: {api_key_details['key']}' \\")
        print("-d '{")
        print(f'  "targetid": "{target_ids[0]}"')
        print("}'")

        # Close MongoDB connection
        client.close()

    except Exception as e:
        print(f"Error creating user: {e}")

if __name__ == "__main__":
    # Example usage
    test_domains = [
        {"domain": "infoziant.com", "name": "Infoziant Production", "environment": "production"},
        {"domain": "staging.infoziant.com", "name": "Infoziant Staging", "environment": "testing"},
        {"domain": "dev.infoziant.com", "name": "Infoziant Development", "environment": "testing"}
    ]
    
    asyncio.run(create_user(
        email="security@infoziant.com",
        name="Security Team",
        company="Infoziant",
        domains=test_domains
    ))