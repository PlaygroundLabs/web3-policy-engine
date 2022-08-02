from typing import Any
from pydantic import BaseModel, Field


class TransactionObject(BaseModel):
    _from: str  # DATA, 20 Bytes - The address the transaction is sent from.
    _to: str  # DATA, 20 Bytes - (optional when creating new contract) The address the transaction is directed to.
    gas: int | None  # QUANTITY - (optional, default: 90000) Integer of the gas provided for the transaction execution. It will return unused gas.
    gasPrice: str | None  # QUANTITY - (optional, default: To-Be-Determined) Integer of the gasPrice used for each paid gas, in Wei.
    value: str | None  # QUANTITY - (optional) Integer of the value sent with this transaction, in Wei.
    data: str | None  # DATA - The compiled code of a contract OR the hash of the invoked method signature and encoded parameters.
    nonce: str | None  # QUANTITY - (optional) Integer of a nonce. This allows to overwrite your own pending transactions that use the same nonce.


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