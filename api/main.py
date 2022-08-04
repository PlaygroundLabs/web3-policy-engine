from typing import Generator
from fastapi import Depends, FastAPI, HTTPException
from fastapi.responses import ORJSONResponse
from web3_policy_engine import PolicyEngine, PolicyEngineError

from .schemas import MessageRequest, RequestResponse, TransactionRequest

app = FastAPI(default_response_class=ORJSONResponse)


def get_policy_engine() -> Generator[PolicyEngine, None, None]:
    policy_engine = PolicyEngine.from_file(
        "api/data/contract_addresses.json",
        "api/data/permissions.yml",
        "api/data/groups.yml",
    )
    try:
        yield policy_engine
    finally:
        pass


@app.post("/message", response_model=RequestResponse)
async def verify_message(
    request: MessageRequest,
    policy_engine: PolicyEngine = Depends(get_policy_engine),
) -> RequestResponse:

    message = request.json_rpc.params[0]

    try:
        policy_engine.verify_message(request.json_rpc.method, message, request.roles)
        return RequestResponse(success=True, message="")
    except PolicyEngineError as e:
        return RequestResponse(success=False, message=str(e))
    raise HTTPException(500, "Shouldn't get here")


@app.post("/transaction", response_model=RequestResponse)
async def verify_transaction(
    request: TransactionRequest,
    policy_engine: PolicyEngine = Depends(get_policy_engine),
) -> RequestResponse:

    try:
        policy_engine.verify_transaction(
            request.json_rpc.method,
            request.json_rpc.params[0].to,
            request.json_rpc.params[0].data,
            request.roles,
        )
        return RequestResponse(success=True, message="")
    except PolicyEngineError as e:
        return RequestResponse(success=False, message=str(e))
    raise HTTPException(500, "Shouldn't get here")
