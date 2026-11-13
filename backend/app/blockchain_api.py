from typing import Optional

from fastapi import APIRouter, HTTPException, Query

from app.blockchain_service import BlockchainUnavailable, LocalBlockchain

router = APIRouter(prefix="/api/blockchain", tags=["Blockchain Audit Explorer"])


def _client() -> LocalBlockchain:
    try:
        return LocalBlockchain()
    except BlockchainUnavailable as error:
        raise HTTPException(status_code=503, detail=str(error)) from error


@router.get("/status")
def blockchain_status() -> dict:
    try:
        return _client().status()
    except HTTPException as error:
        return {"available": False, "reason": error.detail}


@router.get("/history")
def blockchain_history(
    device_id: Optional[str] = Query(default=None, min_length=1),
) -> dict:
    try:
        client = _client()
    except HTTPException as exc:
        return {"available": False, "reason": exc.detail, "chain_id": None, "contract_address": None, "records": []}
    return {
        "available": True,
        "chain_id": client.web3.eth.chain_id,
        "contract_address": client.contract.address,
        "records": client.history(device_id),
    }
