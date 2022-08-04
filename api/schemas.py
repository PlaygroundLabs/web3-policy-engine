from typing import Any
from pydantic import BaseModel, Field


class TransactionObject(BaseModel):
    _from: str|None
    to: str
    gas: str | None
    gasPrice: str | None
    value: str | None
    data: str
    nonce: str | None 


class JsonRpcRequest(BaseModel):
    id: int
    jsonrpc: str
    method: str
    params: list[Any]


class Request(BaseModel):
    json_rpc: JsonRpcRequest
    roles: list[str]


class MessageJsonRpcRequest(JsonRpcRequest):
    params: list[str] = Field(..., min_items=2, max_items=2)


class TransactionJsonRPCRequest(JsonRpcRequest):
    params: list[TransactionObject] = Field(..., min_items=1, max_items=1)


class MessageRequest(Request):
    json_rpc: MessageJsonRpcRequest


class TransactionRequest(Request):
    json_rpc: TransactionJsonRPCRequest


class RequestResponse(BaseModel):
    success: bool
    message: str