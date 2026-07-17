import uvicorn
from fastapi import FastAPI
from contextlib import asynccontextmanager
from api.routers.v1 import auth_routes
from infras.db.mongo import MongoDBManager, get_collection
from core.configs.settings_config import SETTINGS
import datetime
from icecream import ic

async def bootstrap_rsa_keys():
    """Ensure RSA key version '1' exists in MongoDB. Create it if missing."""
    keys_coll = get_collection("keys")
    existing = await keys_coll.find_one({"version": "1"})
    if existing:
        ic("RSA key version '1' already exists — skipping generation.")
        return

    ic("RSA key version '1' not found — generating new key pair...")
    from api.routers.v1.auth_routes import generate_rsa_keypair
    private_pem, public_pem = generate_rsa_keypair()
    await keys_coll.insert_one({
        "version": "1",
        "private_key": private_pem,
        "public_key": public_pem,
        "created_at": datetime.datetime.utcnow()
    })
    ic("RSA key version '1' generated and stored successfully.")

@asynccontextmanager
async def lifespan(app: FastAPI):
    # Startup: Connect to MongoDB
    await MongoDBManager.connect()
    # Bootstrap RSA key version "1" if it doesn't exist
    await bootstrap_rsa_keys()
    yield
    # Shutdown: Close connections
    await MongoDBManager.disconnect()

app = FastAPI(
    title="Authentication Service",
    description="Microservice managing RSA-signed user authentication, tokens, revocations, and credentials via MongoDB",
    lifespan=lifespan
)

app.include_router(auth_routes.router)

if __name__ == "__main__":
    uvicorn.run("main:app", host="0.0.0.0", port=SETTINGS.PORT, reload=True)
