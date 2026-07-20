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
