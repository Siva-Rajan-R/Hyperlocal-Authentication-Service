from motor.motor_asyncio import AsyncIOMotorClient
from core.configs.settings_config import SETTINGS

class MongoDBManager:
    client: AsyncIOMotorClient = None
    db = None

    @classmethod
    async def connect(cls):
        cls.client = AsyncIOMotorClient(SETTINGS.MONGO_URL)
        cls.db = cls.client[SETTINGS.MONGO_DB_NAME]
        
        # Clean up null values to allow sparse unique indexes to work correctly
        await cls.db.users.update_many({"email": None}, {"$unset": {"email": ""}})
        await cls.db.users.update_many({"mobilenumber": None}, {"$unset": {"mobilenumber": ""}})

        import pymongo.errors
        # Normalize existing user emails to lowercase
        cursor = cls.db.users.find({"email": {"$exists": True, "$ne": None}})
        async for doc in cursor:
            raw_email = doc.get("email")
            if isinstance(raw_email, str) and raw_email.strip() and raw_email != raw_email.strip().lower():
                try:
                    await cls.db.users.update_one(
                        {"_id": doc["_id"]},
                        {"$set": {"email": raw_email.strip().lower()}}
                    )
                except pymongo.errors.DuplicateKeyError:
                    # Resolve collision by appending a duplicate suffix
                    await cls.db.users.update_one(
                        {"_id": doc["_id"]},
                        {"$set": {"email": f"{raw_email.strip().lower()}_dup_{doc['_id']}"}}
                    )

        # Ensure Indexes
        await cls.db.users.create_index("user_id", unique=True)
        await cls.db.users.create_index("email", unique=True, sparse=True)
        await cls.db.users.create_index("mobilenumber", unique=True, sparse=True)
        
        await cls.db.keys.create_index("version", unique=True)
        await cls.db.revoked_tokens.create_index("jti", unique=True)

    @classmethod
    async def disconnect(cls):
        if cls.client:
            cls.client.close()

def get_collection(name: str):
    return MongoDBManager.db[name]
