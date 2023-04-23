from fastapi import FastAPI, Request
from typing import Dict
from dotenv import load_dotenv
from fastapi.responses import JSONResponse
import os

import email_sign as E

app = FastAPI()
load_dotenv()

@app.get("/")
def read_root():
    return {"Hello": "World"}

@app.post("/send-email/")
async def send_email(text: str):
    E.generate_key()
    receiver_email = os.getenv("receiver_email")
    subject = "Hello from the other side!"
    body = text
    E.send_email(receiver_email, subject, body)
    return {"message": "Email sent successfully"}

@app.get("/receive-email")
async def receive_email(text: str, signature: str):
    status, signature = E.receive_email(text, signature)
    return {"status": status, "signature": signature}