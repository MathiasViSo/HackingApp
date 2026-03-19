from fastapi import FastAPI, HTTPException, Depends
from pydantic import BaseModel
from typing import List, Optional
from datetime import datetime
from sqlalchemy import create_engine, Column, Integer, String, DateTime, Boolean
from sqlalchemy.orm import declarative_base, sessionmaker, Session

# --- CONFIGURACIÓN DE BASE DE DATOS (SQLite) ---
SQLALCHEMY_DATABASE_URL = "sqlite:///./network_security.db"
engine = create_engine(SQLALCHEMY_DATABASE_URL, connect_args={"check_same_thread": False})
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()

# --- MODELOS DE BASE DE DATOS ---
class DeviceDB(Base):
    __tablename__ = "devices"
    mac_address = Column(String, primary_key=True, index=True)
    last_ip = Column(String)
    manufacturer = Column(String, default="Desconocido")
    is_trusted = Column(Boolean, default=False) # True = Dispositivo de casa, False = Intruso
    first_seen = Column(DateTime, default=datetime.utcnow)
    last_seen = Column(DateTime, default=datetime.utcnow)

class ConnectionLogDB(Base):
    __tablename__ = "connection_logs"
    id = Column(Integer, primary_key=True, index=True)
    mac_address = Column(String)
    timestamp = Column(DateTime, default=datetime.utcnow)
    event_type = Column(String) # "CONECTADO", "ESCANEO_PUERTOS", "ALERTA"

# Crear las tablas en el archivo SQLite
Base.metadata.create_all(bind=engine)

# --- INICIALIZAR FASTAPI ---
app = FastAPI(title="Network Security API - Local Dev")

# Dependencia para obtener la sesión de la DB
def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

# --- MODELOS DE DATOS (PYDANTIC) ---
class DeviceDetectRequest(BaseModel):
    ip_address: str
    mac_address: str
    manufacturer: Optional[str] = "Desconocido"

# --- ENDPOINTS ---

@app.post("/api/v1/detect-intruder")
def detect_intruder(device: DeviceDetectRequest, db: Session = Depends(get_db)):
    """
    Este endpoint recibe un dispositivo visto en la red. 
    Si la MAC no está en la BD, lo marca como intruso.
    Si ya está, actualiza su última conexión.
    """
    db_device = db.query(DeviceDB).filter(DeviceDB.mac_address == device.mac_address).first()
    
    is_intruder = False
    status_message = ""

    if not db_device:
        # Es la primera vez que vemos esta MAC -> ¡Posible Intruso!
        new_device = DeviceDB(
            mac_address=device.mac_address,
            last_ip=device.ip_address,
            manufacturer=device.manufacturer,
            is_trusted=False # Por defecto no confiamos
        )
        db.add(new_device)
        is_intruder = True
        status_message = "¡Alerta! Nuevo dispositivo desconocido detectado en la red."
        
        # Guardar log
        log = ConnectionLogDB(mac_address=device.mac_address, event_type="NUEVO_DISPOSITIVO_DETECTADO")
        db.add(log)
    else:
        # Ya lo conocemos, actualizamos su última IP y fecha
        db_device.last_ip = device.ip_address
        db_device.last_seen = datetime.utcnow()
        is_intruder = not db_device.is_trusted
        
        if is_intruder:
            status_message = "Alerta: Dispositivo no confiable se ha vuelto a conectar."
        else:
            status_message = "Dispositivo confiable conectado."
            
        # Guardar log rutinario
        log = ConnectionLogDB(mac_address=device.mac_address, event_type="CONECTADO")
        db.add(log)

    db.commit()

    return {
        "mac_address": device.mac_address,
        "is_intruder": is_intruder,
        "message": status_message,
        "trusted_status": "Confiable" if not is_intruder else "No Confiable"
    }

@app.get("/api/v1/history")
def get_history(db: Session = Depends(get_db)):
    """
    Devuelve todos los dispositivos que se han conectado históricamente.
    """
    devices = db.query(DeviceDB).all()
    return {"total_devices": len(devices), "devices": devices}

@app.post("/api/v1/trust-device/{mac_address}")
def trust_device(mac_address: str, db: Session = Depends(get_db)):
    """
    Endpoint para que la app (el administrador) marque un dispositivo como "Confiable"
    (ej. el teléfono de la mamá, la Smart TV nueva).
    """
    device = db.query(DeviceDB).filter(DeviceDB.mac_address == mac_address).first()
    if not device:
        raise HTTPException(status_code=404, detail="Dispositivo no encontrado")
    
    device.is_trusted = True
    db.commit()
    return {"message": f"Dispositivo {mac_address} marcado como confiable."}