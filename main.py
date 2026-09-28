"""The Gatekeeper: an agent can only transact with a valid passport, within its limits."""
import jwt
from fastapi import FastAPI, Header, HTTPException
from pydantic import BaseModel

PUBLIC_KEY = open("public_key.pem").read()

app = FastAPI()


class Purchase(BaseModel):
    amount: float
    category: str


@app.post("/transact")
def transact(purchase: Purchase, authorization: str = Header()):
    token = authorization.removeprefix("Bearer ")

    # 1. Verify the passport was signed by the owner's private key.
    try:
        passport = jwt.decode(token, PUBLIC_KEY, algorithms=["RS256"])
    except jwt.InvalidTokenError:
        raise HTTPException(401, "Invalid passport")

    # 2. Check the purchase stays within the passport's scopes.
    if purchase.amount > passport["max_spend"]:
        raise HTTPException(403, "Amount exceeds max_spend")
    if purchase.category != passport["allowed_category"]:
        raise HTTPException(403, "Category not allowed")

    return {"status": "approved", "user_id": passport["user_id"], "amount": purchase.amount}
