from fastapi import FastAPI
from handlers.auth import router

app = FastAPI()

app.include_router(router)