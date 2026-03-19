from fastapi import FastAPI, HTTPException, Depends
from pydantic import BaseModel
from typing import List, Optional
from datetime import datetime
from sqlalchemy import create_engine, Column, Integer, String, DateTime, Boolean, Float
from sqlalchemy.orm import declarative_base, sessionmaker, Session
# NUEVO: Importamos AsyncMacLookup para que no choque con FastAPI
from mac_vendor_lookup import AsyncMacLookup, VendorNotFoundError 

# --- CONFIGURACIÓN DE BASE DE DATOS (SQLite) ---
SQLALCHEMY_DATABASE_URL = "sqlite:///./network_security.db"
engine = create_engine(SQLALCHEMY_DATABASE_URL, connect_args={"check_same_thread": False})
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()

class DeviceDB(Base):
    __tablename__ = "devices"
    mac_address = Column(String, primary_key=True, index=True)
    last_ip = Column(String)
    manufacturer = Column(String, default="Desconocido")
    is_trusted = Column(Boolean, default=False)
    first_seen = Column(DateTime, default=datetime.utcnow)
    last_seen = Column(DateTime, default=datetime.utcnow)

class WifiMapDB(Base):
    __tablename__ = "wifi_heatmap"
    id = Column(Integer, primary_key=True, index=True)
    zone_name = Column(String)
    x_coordinate = Column(Float)
    y_coordinate = Column(Float)
    signal_dbm = Column(Integer)
    timestamp = Column(DateTime, default=datetime.utcnow)

Base.metadata.create_all(bind=engine)

# --- INICIALIZACIÓN ---
app = FastAPI(title="Network Security API")
mac_lookup = AsyncMacLookup() # Versión asíncrona segura

def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

# Evento de inicio seguro
@app.on_event("startup")
async def startup_event():
    try:
        await mac_lookup.update_vendors() # Añadimos await
        print("Base de datos OUI actualizada.")
    except Exception as e:
        print(f"Error al actualizar OUI: {e}")

# --- MODELOS PYDANTIC ---
class DeviceDetectRequest(BaseModel):
    ip_address: str
    mac_address: str

class DeviceScanRequest(BaseModel):
    ip_address: str
    open_ports: List[int] = []

class PortAnalysis(BaseModel):
    port: int
    service: str
    risk_level: str
    recommendation: str

class DeviceAnalysisResponse(BaseModel):
    ip_address: str
    security_score: int
    port_analysis: List[PortAnalysis]

class WifiSignalPoint(BaseModel):
    zone_name: str
    x_coordinate: float
    y_coordinate: float
    signal_dbm: int

# --- ENDPOINT 1: Detección rápida de red (HomeScreen) ---
@app.post("/api/v1/detect-device")
async def detect_device(device: DeviceDetectRequest, db: Session = Depends(get_db)):
    fabricante_real = "Desconocido"
    try:
        # Añadimos await para no bloquear el Event Loop
        fabricante_real = await mac_lookup.lookup(device.mac_address)
    except Exception:
        pass # Si la MAC es un hash simulado, pasará por aquí

    db_device = db.query(DeviceDB).filter(DeviceDB.mac_address == device.mac_address).first()
    is_intruder = False

    if not db_device:
        new_device = DeviceDB(
            mac_address=device.mac_address, last_ip=device.ip_address,
            manufacturer=fabricante_real, is_trusted=False
        )
        db.add(new_device)
        is_intruder = True
    else:
        db_device.last_ip = device.ip_address
        db_device.last_seen = datetime.utcnow()
        is_intruder = not db_device.is_trusted

    db.commit()

    recomendacion = "Dispositivo estándar."
    if "Hikvision" in fabricante_real or "Dahua" in fabricante_real:
        recomendacion = "⚠️ Posible Cámara IP."
    elif "Samsung" in fabricante_real or "LG" in fabricante_real:
        recomendacion = "Posible Smart TV."

    return {
        "mac_address": device.mac_address,
        "manufacturer": fabricante_real,
        "is_intruder": is_intruder,
        "recommendation": recomendacion
    }

# --- ENDPOINT 2: Auditoría de Puertos (DeviceDetailsScreen) ---
@app.post("/api/v1/analyze-device", response_model=DeviceAnalysisResponse)
async def analyze_device(device: DeviceScanRequest):
    KNOWN_PORTS = {
        21: {"service": "FTP", "risk": "Alto", "rec": "Puerto no cifrado. Desactívalo."},
        22: {"service": "SSH", "risk": "Medio", "rec": "Revisa contraseñas por defecto."},
        80: {"service": "HTTP", "risk": "Medio", "rec": "Tráfico web no seguro."},
        443: {"service": "HTTPS", "risk": "Bajo", "rec": "Conexión cifrada estándar."},
        554: {"service": "RTSP", "risk": "Alto", "rec": "Cámara IP detectada."},
        8080: {"service": "HTTP-Alt", "risk": "Medio", "rec": "Servicio de router/IoT."}
    }
    
    analysis_results = []
    score = 100
    for port in device.open_ports:
        if port in KNOWN_PORTS:
            p = KNOWN_PORTS[port]
            analysis_results.append(PortAnalysis(port=port, service=p["service"], risk_level=p["risk"], recommendation=p["rec"]))
            if p["risk"] == "Alto": score -= 30
            elif p["risk"] == "Medio": score -= 10
        else:
            analysis_results.append(PortAnalysis(port=port, service="Desconocido", risk_level="Desconocido", recommendation="Analizar uso."))
            score -= 5
            
    return DeviceAnalysisResponse(ip_address=device.ip_address, security_score=max(0, score), port_analysis=analysis_results)

# --- ENDPOINTS 3 y 4: Mapa Wi-Fi (WifiMapScreen) ---
@app.post("/api/v1/wifi-map/record")
async def record_wifi_signal(point: WifiSignalPoint, db: Session = Depends(get_db)):
    new_point = WifiMapDB(zone_name=point.zone_name, x_coordinate=point.x_coordinate, y_coordinate=point.y_coordinate, signal_dbm=point.signal_dbm)
    db.add(new_point)
    db.commit()
    router_rec = "Señal estable."
    if point.signal_dbm < -80: router_rec = f"Señal muy débil en {point.zone_name}. Usa repetidor."
    return {"status": "recorded", "recommendation": router_rec}

@app.get("/api/v1/wifi-map/data")
async def get_wifi_map(db: Session = Depends(get_db)):
    points = db.query(WifiMapDB).all()
    return {"total_points": len(points), "heatmap_data": points}