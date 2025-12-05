import redis.asyncio as redis
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi_limiter import FastAPILimiter
from src.routes import contacts, auth, users
from src.conf.config import settings

import contextlib


@contextlib.asynccontextmanager
async def lifespan(app: FastAPI):
    r = await redis.Redis(host='redis', port=6379, db=0, encoding="utf-8", decode_responses=True)
    await FastAPILimiter.init(r)
    yield

app = FastAPI(lifespan=lifespan)

app.include_router(contacts.router, prefix="/api")
app.include_router(auth.router, prefix="/api")
app.include_router(users.router, prefix="/api")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.get("/")
def read_root():
    return {"message": "Hello World"}
