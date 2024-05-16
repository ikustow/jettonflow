import asyncio
from TonTools import *
import base64
import json
import requests
from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
from tonsdk.contract.token.nft import NFTItem
from tonsdk.utils import to_nano, bytes_to_b64str, Address
from tonsdk.contract.wallet import Wallets, WalletVersionEnum
from cryptography.fernet import Fernet
from model import CreateMessageRequest


def decrypt_strings(encrypted_message, key):
    fernet = Fernet(key)
    decrypted_message = fernet.decrypt(encrypted_message).decode()
    return decrypted_message.split("\n")

app = FastAPI()

@app.post("/send_message")
async def send_message(request: CreateMessageRequest):
    key = request.key.encode()
    mnemonic = request.mnemonic.encode()
    JETTON_MASTER = request.master
    new_owner_address = request.new_owner_address
    decrypted_mnemonic = decrypt_strings(mnemonic, key)

    if not mnemonic:
        raise HTTPException(status_code=400, detail="Mnemonic cannot be empty")

    try:
        client = TonCenterClient(orbs_access=True)
        your_wallet = Wallet(provider=client, mnemonics=decrypted_mnemonic, version='v4r2')

        response =  await your_wallet.transfer_jetton(
            destination_address=new_owner_address, 
            jetton_master_address=JETTON_MASTER,
            jettons_amount=1
        )
        response_details = f"This is your response including the variable: {key},  {decrypted_mnemonic}"
        return {"message": "Success", "response": response_details}

    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))



