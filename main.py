from fastapi import FastAPI, HTTPException, Depends
from pydantic import BaseModel
from typing import List, Optional
from datetime import datetime
from sqlalchemy import create_engine, Column, Integer, String, DateTime, Boolean, Float
from sqlalchemy.orm import declarative_base, sessionmaker, Session
from mac_vendor_lookup import MacLookup, VendorNotFoundError

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
    is_trusted = Column(Boolean, default=False)
    first_seen = Column(DateTime, default=datetime.utcnow)
    last_seen = Column(DateTime, default=datetime.utcnow)

class WifiMapDB(Base):
    __tablename__ = "wifi_heatmap"
    id = Column(Integer, primary_key=True, index=True)
    zone_name = Column(String) # Ej: "Sala", "Cuarto Principal"
    x_coordinate = Column(Float) # Coordenada X del Canvas de Flutter
    y_coordinate = Column(Float) # Coordenada Y del Canvas de Flutter
    signal_dbm = Column(Integer) # Ej: -50 (Excelente), -85 (Mala)
    timestamp = Column(DateTime, default=datetime.utcnow)

Base.metadata.create_all(bind=engine)

# --- INICIALIZAR FASTAPI Y LIBRERÍAS ---
app = FastAPI(title="Network Security & Monitor API")
mac_lookup = MacLookup()

def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

# Evento de inicio: Actualiza la lista de fabricantes de tarjetas de red
@app.on_event("startup")
async def startup_event():
    try:
        # Descarga la lista oficial de OUI al arrancar el servidor
        mac_lookup.update_vendors()
        print("Base de datos de fabricantes MAC actualizada correctamente.")
    except Exception as e:
        print(f"No se pudo actualizar la lista MAC (revisa tu conexión): {e}")

# --- MODELOS PYDANTIC (ENTRADA DE FLUTTER) ---
class DeviceDetectRequest(BaseModel):
    ip_address: str
    mac_address: str

class WifiSignalPoint(BaseModel):
    zone_name: str
    x_coordinate: float
    y_coordinate: float
    signal_dbm: int

# --- ENDPOINTS ---

@app.post("/api/v1/detect-device")
def detect_device(device: DeviceDetectRequest, db: Session = Depends(get_db)):
    """
    Detecta el dispositivo, busca su fabricante real (OUI) y lo registra.
    """
    # 1. Identificar el Fabricante usando la librería
    fabricante_real = "Desconocido"
    try:
        # La librería lee los primeros 3 bytes de la MAC (Ej: 00:1A:2B)
        fabricante_real = mac_lookup.lookup(device.mac_address)
    except VendorNotFoundError:
        fabricante_real = "Fabricante Oculto o Desconocido"

    # 2. Lógica de Base de Datos (Detección de Intrusos)
    db_device = db.query(DeviceDB).filter(DeviceDB.mac_address == device.mac_address).first()
    is_intruder = False

    if not db_device:
        # ¡Nuevo dispositivo!
        new_device = DeviceDB(
            mac_address=device.mac_address,
            last_ip=device.ip_address,
            manufacturer=fabricante_real, # Guardamos el fabricante real
            is_trusted=False
        )
        db.add(new_device)
        is_intruder = True
        status_message = "¡Alerta! Nuevo dispositivo IoT detectado."
    else:
        # Ya conocido
        db_device.last_ip = device.ip_address
        db_device.last_seen = datetime.utcnow()
        is_intruder = not db_device.is_trusted
        status_message = "Dispositivo ya registrado."

    db.commit()

    # Pequeño motor de recomendaciones basado en fabricante
    recomendacion = "Dispositivo estándar."
    if "Hikvision" in fabricante_real or "Dahua" in fabricante_real:
        recomendacion = "⚠️ Posible Cámara IP detectada. Verifica puertos RTSP (554)."
    elif "Samsung" in fabricante_real or "LG" in fabricante_real:
        recomendacion = "Posible Smart TV."
    elif "Espressif" in fabricante_real: # Fabricante común de chips para IoT casero / Arduino
        recomendacion = "⚠️ Dispositivo IoT genérico (posible sensor o cámara casera)."

    return {
        "mac_address": device.mac_address,
        "manufacturer": fabricante_real,
        "is_intruder": is_intruder,
        "message": status_message,
        "recommendation": recomendacion
    }

# --- ENDPOINTS DEL MAPA WI-FI ---

@app.post("/api/v1/wifi-map/record")
def record_wifi_signal(point: WifiSignalPoint, db: Session = Depends(get_db)):
    """
    Flutter envía este endpoint cada vez que el usuario da un paso en su casa
    y registra la intensidad de la señal.
    """
    new_point = WifiMapDB(
        zone_name=point.zone_name,
        x_coordinate=point.x_coordinate,
        y_coordinate=point.y_coordinate,
        signal_dbm=point.signal_dbm
    )
    db.add(new_point)
    db.commit()
    
    # Lógica de recomendación de Router
    router_rec = "Señal estable."
    if point.signal_dbm < -80:
        router_rec = f"Señal muy débil ({point.signal_dbm} dBm) en {point.zone_name}. Considera un repetidor Mesh aquí."

    return {"status": "recorded", "recommendation": router_rec}

@app.get("/api/v1/wifi-map/data")
def get_wifi_map(db: Session = Depends(get_db)):
    """
    Flutter llama a este endpoint para obtener todos los puntos y dibujar el mapa de calor visual.
    """
    points = db.query(WifiMapDB).all()
    return {"total_points": len(points), "heatmap_data": points}