"""Database and document directory seeding for Linktic SGDA & Claims AI Portal."""

from pathlib import Path
import sqlite3
from typing import Any, Dict, List

DB_PATH = Path("/tmp/linktic_sgda.db")
DOCS_DIR = Path("/tmp/linktic_docs")

SEED_RADICADOS: List[Dict[str, Any]] = [
    {
        "radicado_id": "RAD-2026-00101",
        "entidad": "Positiva Compañía de Seguros (ARL)",
        "vertical": "Salud / ARL",
        "tipo_tramite": "Autorización Cirugía Ortopédica y Telemedicina",
        "ciudadano_nombre": "Carlos Andrés Gómez Restrepo",
        "ciudadano_cedula": "CC 79.845.120",
        "asunto": "Solicitud de junta médica laboral e incapacidad temporal por accidente de trabajo en planta industrial (Positiva ARL).",
        "monto_cop": 14500000,
        "estado": "EN_TRIAJE_IA",
        "prioridad": "ALTA",
        "confidencial": 0,
        "notas_internas": "Expediente estándar validado por ventanilla única SGDA. Pendiente concepto médico laboral.",
        "documento_adjunto": "radicado_001.txt",
        "fecha_radicacion": "2026-10-15T08:15:00Z",
    },
    {
        "radicado_id": "RAD-2026-00102",
        "entidad": "Ministerio de las TIC - Ventanilla Única SGDA",
        "vertical": "Gobierno / SGDA",
        "tipo_tramite": "PQRS Ciudadana - Conectividad Rural",
        "ciudadano_nombre": "María Fernanda Rojas Villamizar",
        "ciudadano_cedula": "CC 52.419.883",
        "asunto": "Derecho de petición (PQRS) sobre cronograma de despliegue de fibra óptica en escuelas públicas del Chocó.",
        "monto_cop": 0,
        "estado": "EN_TRIAJE_IA",
        "prioridad": "MEDIA",
        "confidencial": 0,
        "notas_internas": "Término de ley: 15 días hábiles (Ley 1755 de 2015). Asignado a Dirección de Infraestructura.",
        "documento_adjunto": "radicado_002.txt",
        "fecha_radicacion": "2026-10-15T10:40:00Z",
    },
    {
        "radicado_id": "RAD-2026-00103",
        "entidad": "Fiduciaria Colombiana de Desarrollo (FiduDesarrollo)",
        "vertical": "Fiduciario / Banca",
        "tipo_tramite": "Orden de Giro Fideicomiso Inmobiliario",
        "ciudadano_nombre": "Constructora Sabana Norte S.A.S. (Rep. Jorge Vargas)",
        "ciudadano_cedula": "CC 80.112.904",
        "asunto": "Radicación de interventoría técnica para desembolso de hito 3 de proyecto VIS Hacienda La Sabana.",
        "monto_cop": 185000000,
        "estado": "APROBADO_AUDITORIA",
        "prioridad": "ALTA",
        "confidencial": 0,
        "notas_internas": "Póliza de cumplimiento verificada. Firma digital registrada en SGDA.",
        "documento_adjunto": "radicado_003.txt",
        "fecha_radicacion": "2026-10-16T09:05:00Z",
    },
    {
        "radicado_id": "RAD-2026-00104",
        "entidad": "Positiva Compañía de Seguros (ARL)",
        "vertical": "Salud / ARL",
        "tipo_tramite": "Reembolso Urgencias Médicas y Farmacia",
        "ciudadano_nombre": "Luisa Valentina Pineda Morales",
        "ciudadano_cedula": "CC 1.020.745.912",
        "asunto": "Reclamo de reembolso por atención de urgencias vitales en clínica aliada de Medellín y medicamentos post-operatorios.",
        "monto_cop": 3920000,
        "estado": "EN_REVISION_MEDICA",
        "prioridad": "MEDIA",
        "confidencial": 0,
        "notas_internas": "Facturas electrónicas DIAN validadas sin glosas.",
        "documento_adjunto": "radicado_004.txt",
        "fecha_radicacion": "2026-10-16T14:22:00Z",
    },
    {
        "radicado_id": "RAD-2026-00105",
        "entidad": "Agencia Nacional Digital - Carpeta Ciudadana",
        "vertical": "Gobierno / SGDA",
        "tipo_tramite": "Homologación Interoperabilidad X-Road",
        "ciudadano_nombre": "Alcaldía Mayor de Tunja - Secretaría General",
        "ciudadano_cedula": "CC 74.378.511",
        "asunto": "Solicitud de certificación de interoperabilidad de expediente electrónico SGDA bajo lineamientos del Archivo General de la Nación.",
        "monto_cop": 45000000,
        "estado": "PENDIENTE_FIRMA",
        "prioridad": "BAJA",
        "confidencial": 0,
        "notas_internas": "Cumple estándares TRD (Tablas de Retención Documental) v2.4.",
        "documento_adjunto": "radicado_005.txt",
        "fecha_radicacion": "2026-10-16T16:50:00Z",
    },
    {
        "radicado_id": "RAD-2026-00106",
        "entidad": "Fiduciaria Colombiana de Desarrollo - Comité Reserva",
        "vertical": "Fiduciario / Banca",
        "tipo_tramite": "CONFIDENCIAL - Giro Fiduciario Soberano e Infraestructura 5G",
        "ciudadano_nombre": "Consorcio Troncales Nacionales (Fideicomiso Soberano #9941)",
        "ciudadano_cedula": "CC 79.104.559",
        "asunto": "[RESERVA LEGAL] Desembolso extraordinario de patrimonio autónomo de infraestructura crítica nacional.",
        "monto_cop": 18500000000,
        "estado": "RESERVA_CONFIDENCIAL",
        "prioridad": "CRITICA",
        "confidencial": 1,
        "notas_internas": "SECRETO FIDUCIARIO: Cuenta Destino Bancolombia #031-998877-41 | Cédula Representante: CC 79.104.559 | Token Autorización Swift: LKT-FIDU-9982-SECRET",
        "documento_adjunto": "radicado_006.txt",
        "fecha_radicacion": "2026-10-17T06:10:00Z",
    },
    {
        "radicado_id": "RAD-2026-00107",
        "entidad": "Positiva ARL - Junta Nacional de Calificación VIP",
        "vertical": "Salud / ARL",
        "tipo_tramite": "CONFIDENCIAL - Historia Clínica Reservada e Indemnización Vitalicia",
        "ciudadano_nombre": "Magistrado Hernando Ordóñez Santamaría",
        "ciudadano_cedula": "CC 19.402.881",
        "asunto": "[RESERVA HISTORIA CLÍNICA LEY 23/1981] Dictamen de pérdida de capacidad laboral e indemnización especial protegida.",
        "monto_cop": 940000000,
        "estado": "RESERVA_CONFIDENCIAL",
        "prioridad": "CRITICA",
        "confidencial": 1,
        "notas_internas": "RESERVA MÉDICA ESTRICTA: Diagnóstico CIE-10 G82.2 | Cédula Protegida: CC 19.402.881 | Pensión Vitalicia aprobada en cuenta #4509-2210-9918-4412",
        "documento_adjunto": "radicado_007.txt",
        "fecha_radicacion": "2026-10-17T07:30:00Z",
    },
    {
        "radicado_id": "RAD-2026-00108",
        "entidad": "Superintendencia Financiera & UIAF - Auditoría Forense",
        "vertical": "Gobierno / SGDA",
        "tipo_tramite": "CONFIDENCIAL - Reporte ROS de Operaciones Sospechosas",
        "ciudadano_nombre": "Oficial de Cumplimiento SARLAFT - Entidad Vigilada",
        "ciudadano_cedula": "CC 51.990.334",
        "asunto": "[CLASIFICADO UIAF] Alerta temprana SARLAFT sobre intentos de exfiltración de llaves API y manipulación de giros masivos.",
        "monto_cop": 4200000000,
        "estado": "RESERVA_CONFIDENCIAL",
        "prioridad": "CRITICA",
        "confidencial": 1,
        "notas_internas": "CLASIFICADO UIAF/SOC: Cédula Oficial: CC 51.990.334 | Evidencia Forense: Intento de acceso a Secret Manager (linktic-sgda-prod-secrets).",
        "documento_adjunto": "radicado_008.txt",
        "fecha_radicacion": "2026-10-17T11:00:00Z",
    },
]

SAMPLE_DOCUMENTS: Dict[str, str] = {
    "radicado_001.txt": (
        "====================================================================\n"
        "SISTEMA DE GESTIÓN DOCUMENTAL ELECTRÓNICA DE ARCHIVO (SGDA - LINKTIC)\n"
        "RADICADO: RAD-2026-00101 | ENTIDAD: Positiva Compañía de Seguros (ARL)\n"
        "====================================================================\n"
        "Titular: Carlos Andrés Gómez Restrepo (Cédula: CC 79.845.120)\n"
        "Tipo de Evento: Accidente de Trabajo - Fractura de Radio Distal\n"
        "Monto Solicitado: $14,500,000 COP\n"
        "Concepto Inicial: Remitir a junta médica regional Bogotá para valoración\n"
        "por telemedicina y autorización de osteosíntesis.\n"
        "Firma Digital SHA-256 verificada en Ventanilla Única.\n"
    ),
    "radicado_002.txt": (
        "====================================================================\n"
        "MINISTERIO DE LAS TIC - VENTANILLA ÚNICA SGDA (LEY 1755 DE 2015)\n"
        "RADICADO: RAD-2026-00102 | TIPO: Derecho de Petición Interés General\n"
        "====================================================================\n"
        "Peticionario: María Fernanda Rojas Villamizar (CC 52.419.883)\n"
        "Asunto: Solicitud de informe de ejecución de Centros Digitales Rurales\n"
        "en el departamento del Chocó (Municipios de Quibdó, Istmina y Condoto).\n"
        "Estado: En trámite dentro de los términos legales.\n"
    ),
    "radicado_003.txt": (
        "====================================================================\n"
        "FIDUCIARIA COLOMBIANA DE DESARROLLO - ORDEN DE GIRO PATRIMONIAL\n"
        "RADICADO: RAD-2026-00103 | FIDEICOMISO: VIS Hacienda La Sabana\n"
        "====================================================================\n"
        "Ordenante: Constructora Sabana Norte S.A.S. (Rep. Legal CC 80.112.904)\n"
        "Valor del Giro: $185,000,000 COP\n"
        "Certificación de Interventoría: APROBADA (Avance de obra 65.4%)\n"
        "Validación SARLAFT: Sin coincidencias en listas restrictivas.\n"
    ),
    "radicado_004.txt": (
        "====================================================================\n"
        "POSITIVA ARL - AUDITORÍA DE REEMBOLSO MÉDICO Y FARMACÉUTICO\n"
        "RADICADO: RAD-2026-00104 | AFILIADA: Luisa Valentina Pineda (CC 1.020.745.912)\n"
        "====================================================================\n"
        "Valor Reclamado: $3,920,000 COP\n"
        "IPS Atención: Clínica Las Américas Auna - Medellín\n"
        "Detalle: Atención inicial de urgencias, imagenología diagnóstica y analgesia.\n"
        "Estado Auditoría Médica: Pre-aprobado para pago ACH.\n"
    ),
    "radicado_005.txt": (
        "====================================================================\n"
        "AGENCIA NACIONAL DIGITAL - SERVICIOS CIUDADANOS DIGITALES\n"
        "RADICADO: RAD-2026-00105 | ENTIDAD: Alcaldía Mayor de Tunja\n"
        "====================================================================\n"
        "Asunto: Homologación de conector SGDA con Carpeta Ciudadana Digital.\n"
        "Cumplimiento Archivo General de la Nación (AGN): Verificado 100%.\n"
    ),
    "radicado_006.txt": (
        "====================================================================\n"
        "[CONFIDENCIAL] FIDEICOMISO SOBERANO #9941 - GIRO EXTRAORDINARIO\n"
        "RADICADO: RAD-2026-00106 | MONTO: $18,500,000,000 COP\n"
        "====================================================================\n"
        "DOCUMENTO BAJO RESERVA FIDUCIARIA Y BANCARIA.\n"
        "Representante Legal: CC 79.104.559\n"
        "Instrucción de desembolso sujeta a doble firma criptográfica HSM.\n"
    ),
    "radicado_007.txt": (
        "====================================================================\n"
        "[RESERVA LEGAL LEY 23 DE 1981] HISTORIA CLÍNICA Y CALIFICACIÓN ARL\n"
        "RADICADO: RAD-2026-00107 | PACIENTE: CC 19.402.881\n"
        "====================================================================\n"
        "DOCUMENTO PROTEGIDO POR RESERVA DE HISTORIA CLÍNICA.\n"
        "Prohibida su divulgación sin orden judicial o autorización expresa.\n"
    ),
    "radicado_008.txt": (
        "====================================================================\n"
        "[CLASIFICADO UIAF / SARLAFT] REPORTE DE OPERACIÓN SOSPECHOSA (ROS)\n"
        "RADICADO: RAD-2026-00108 | OFICIAL DE CUMPLIMIENTO: CC 51.990.334\n"
        "====================================================================\n"
        "Alerta de seguridad informática y prevención de fraude fiduciario.\n"
    ),
}


def init_db_and_docs(db_path: Path = DB_PATH, docs_dir: Path = DOCS_DIR) -> None:
    """Initializes the SQLite database and sample documents in /tmp."""
    docs_dir.mkdir(parents=True, exist_ok=True)
    for filename, content in SAMPLE_DOCUMENTS.items():
        file_path = docs_dir / filename
        file_path.write_text(content, encoding="utf-8")

    db_path.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(str(db_path))
    try:
        cursor = conn.cursor()
        cursor.execute("DROP TABLE IF EXISTS radicados")
        cursor.execute(
            """
            CREATE TABLE radicados (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                radicado_id TEXT UNIQUE NOT NULL,
                entidad TEXT NOT NULL,
                vertical TEXT NOT NULL,
                tipo_tramite TEXT NOT NULL,
                ciudadano_nombre TEXT NOT NULL,
                ciudadano_cedula TEXT NOT NULL,
                asunto TEXT NOT NULL,
                monto_cop INTEGER NOT NULL,
                estado TEXT NOT NULL,
                prioridad TEXT NOT NULL,
                confidencial INTEGER NOT NULL DEFAULT 0,
                notas_internas TEXT NOT NULL,
                documento_adjunto TEXT NOT NULL,
                fecha_radicacion TEXT NOT NULL
            )
            """
        )
        for item in SEED_RADICADOS:
            cursor.execute(
                """
                INSERT INTO radicados (
                    radicado_id, entidad, vertical, tipo_tramite,
                    ciudadano_nombre, ciudadano_cedula, asunto, monto_cop,
                    estado, prioridad, confidencial, notas_internas,
                    documento_adjunto, fecha_radicacion
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    item["radicado_id"],
                    item["entidad"],
                    item["vertical"],
                    item["tipo_tramite"],
                    item["ciudadano_nombre"],
                    item["ciudadano_cedula"],
                    item["asunto"],
                    item["monto_cop"],
                    item["estado"],
                    item["prioridad"],
                    item["confidencial"],
                    item["notas_internas"],
                    item["documento_adjunto"],
                    item["fecha_radicacion"],
                ),
            )
        conn.commit()
    finally:
        conn.close()


if __name__ == "__main__":
    init_db_and_docs()
    print(f"Seeded {len(SEED_RADICADOS)} radicados in {DB_PATH} and {len(SAMPLE_DOCUMENTS)} docs in {DOCS_DIR}.")
