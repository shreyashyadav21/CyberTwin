import json
import uuid
from typing import List
from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session

from backend.app.models.database import get_db
from backend.app.schemas.network import (
    NetworkCreateSchema,
    NetworkUpdateSchema,
    NetworkResponseSchema,
    DeviceSchema,
    ConnectionSchema,
    NetworkValidationResult
)
from backend.app.services.network_service import NetworkService

router = APIRouter(prefix="/api/networks", tags=["networks"])

@router.get("", response_model=List[NetworkResponseSchema])
def list_networks(db: Session = Depends(get_db)):
    return NetworkService.list_networks(db)

@router.post("", response_model=NetworkResponseSchema, status_code=status.HTTP_201_CREATED)
def create_network(payload: NetworkCreateSchema, db: Session = Depends(get_db)):
    return NetworkService.create_network(db, payload)

@router.get("/{network_id}", response_model=NetworkResponseSchema)
def get_network(network_id: str, db: Session = Depends(get_db)):
    net = NetworkService.get_network(db, network_id)
    if not net:
        raise HTTPException(status_code=404, detail="Network model not found")
    return net

@router.put("/{network_id}", response_model=NetworkResponseSchema)
def update_network(network_id: str, payload: NetworkUpdateSchema, db: Session = Depends(get_db)):
    updated = NetworkService.update_network(db, network_id, payload)
    if not updated:
        raise HTTPException(status_code=404, detail="Network model not found")
    return updated

@router.delete("/{network_id}", status_code=status.HTTP_204_NO_CONTENT)
def delete_network(network_id: str, db: Session = Depends(get_db)):
    success = NetworkService.delete_network(db, network_id)
    if not success:
        raise HTTPException(status_code=404, detail="Network model not found")
    return None

@router.post("/{network_id}/devices", response_model=NetworkResponseSchema)
def add_device(network_id: str, device: DeviceSchema, db: Session = Depends(get_db)):
    updated = NetworkService.add_device(db, network_id, device)
    if not updated:
        raise HTTPException(status_code=404, detail="Network model not found")
    return updated

@router.put("/devices/{device_id}", response_model=NetworkResponseSchema)
def update_device(device_id: str, device: DeviceSchema, db: Session = Depends(get_db)):
    updated = NetworkService.update_device_by_id(db, device_id, device)
    if not updated:
        raise HTTPException(status_code=404, detail="Device not found")
    return updated

@router.delete("/devices/{device_id}", response_model=NetworkResponseSchema)
def delete_device(device_id: str, db: Session = Depends(get_db)):
    updated = NetworkService.delete_device_by_id(db, device_id)
    if not updated:
        raise HTTPException(status_code=404, detail="Device not found")
    return updated

@router.post("/{network_id}/connections", response_model=NetworkResponseSchema)
def add_connection(network_id: str, connection: ConnectionSchema, db: Session = Depends(get_db)):
    updated = NetworkService.add_connection(db, network_id, connection)
    if not updated:
        raise HTTPException(status_code=404, detail="Network model not found")
    return updated

@router.post("/{network_id}/validate", response_model=NetworkValidationResult)
def validate_network(network_id: str, db: Session = Depends(get_db)):
    val = NetworkService.validate_network_by_id(db, network_id)
    if not val:
        raise HTTPException(status_code=404, detail="Network model not found")
    return val

@router.post("/{network_id}/isolate/{device_id}", response_model=NetworkResponseSchema)
def isolate_device_toggle(network_id: str, device_id: str, isolate: bool = True, db: Session = Depends(get_db)):
    updated = NetworkService.isolate_device(db, device_id, isolate=isolate)
    if not updated:
        raise HTTPException(status_code=404, detail="Device or network not found")
    return updated

