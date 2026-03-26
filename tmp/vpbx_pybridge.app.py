from __future__ import annotations

import ipaddress
import logging
import os
import random
import re
import socket
from pathlib import Path
from typing import Any, Awaitable, Callable
from urllib.parse import quote_plus, unquote_plus

import httpx
import pymssql
from fastapi import BackgroundTasks, FastAPI, Request
from fastapi.responses import JSONResponse, PlainTextResponse

try:
    import pyodbc
except Exception:  # pragma: no cover
    pyodbc = None

APP_NAME = "VPBX ASP Compatibility (Python)"
ASP_SOURCE_DIR = Path(os.getenv("VPBX_ASP_SOURCE_DIR", "/home/kuru.ravi/VPBX"))

DEFAULT_DB_USER = os.getenv("VPBX_DB_USER", "awamjanta")
DEFAULT_DB_PASSWORD = os.getenv("VPBX_DB_PASSWORD", "Pad3Dafa@Ghar")
DEFAULT_DB_HOST = os.getenv("VPBX_DB_HOST", "127.0.0.1")
DEFAULT_DB_PORT = int(os.getenv("VPBX_DB_PORT", "1433"))
DEFAULT_DB_MODE = os.getenv("VPBX_DB_MODE", "mssql").strip().lower()  # mssql | odbc
DB_TIMEOUT_SECONDS = int(os.getenv("VPBX_DB_TIMEOUT_SECONDS", "8"))

DB_KEY_TO_DATABASE = {
    "TelcanAccounts": os.getenv("VPBX_DATABASE_TelcanAccounts", "TelcanAccounts"),
    "TelcanRates": os.getenv("VPBX_DATABASE_TelcanRates", "TelcanRates"),
    "TelcanInternet": os.getenv("VPBX_DATABASE_TelcanInternet", "TelcanInternet"),
    "TelcanLCR": os.getenv("VPBX_DATABASE_TelcanLCR", "TelcanLCR"),
    "TelcanSwitch": os.getenv("VPBX_DATABASE_TelcanSwitch", "TelcanSwitch"),
    "TelcanRecording": os.getenv("VPBX_DATABASE_TelcanRecording", "TelcanRecording"),
    "TelcanSQLLogs": os.getenv("VPBX_DATABASE_TelcanSQLLogs", "TelcanSQLLogs"),
    "TelcanQueue": os.getenv("VPBX_DATABASE_TelcanQueue", "TelcanQueue"),
    "TelcanMonitor": os.getenv("VPBX_DATABASE_TelcanMonitor", "TelcanMonitor"),
    "TelcanCalls": os.getenv("VPBX_DATABASE_TelcanCalls", "TelcanCalls"),
    "TelcanCalls_NYDB6": os.getenv("VPBX_DATABASE_TelcanCalls_NYDB6", "TelcanCalls_NYDB6"),
    "TelcanRecovery_DBS2": os.getenv("VPBX_DATABASE_TelcanRecovery_DBS2", "TelcanRecovery_DBS2"),
    "TelcanRecovery_DBS4": os.getenv("VPBX_DATABASE_TelcanRecovery_DBS4", "TelcanRecovery_DBS4"),
    "TelcanVoIP": os.getenv("VPBX_DATABASE_TelcanVoIP", "TelcanVoIP"),
}
AVAILABLE_ONLY_MODE = os.getenv("VPBX_AVAILABLE_ONLY_MODE", "0").strip().lower() in {"1", "true", "yes", "on"}

MIGRATED_ENDPOINTS = {
    "test.asp",
    "servicetypeget.asp",
    "servicetypegetv2.asp",
    "inbounddidserveripget.asp",
    "getlinenocount.asp",
    "getcalleridv3.asp",
    "setbusy2.asp",
    "faxstatusv2.asp",
    "createfaxid.asp",
    "faxlookup.asp",
    "faxstatus.asp",
    "faxstatuscheck.asp",
    "faxstatusupdate.asp",
    "callsetupv308.asp",
    "callsetupv308-dev.asp",
    "callend.asp",
    "blindtransferinfo.asp",
    "leg2connected.asp",
    "updatecallstatus.asp",
    "voicemaildeletelist.asp",
    "voicemail2.asp",
    "vmindicatorget.asp",
    "transcriptionsave.asp",
    "getcallerid.asp",
    "getcallerid-dev.asp",
    "providerlookupv3.asp",
    "getproviderinfo.asp",
    "getinboundlineinfov405.asp",
    "asterisklookupv2.asp",
    "getratesv301.asp",
    "getratesv305.asp",
    "getratesv306.asp",
    "switchconfiggetold.asp",
    "voipdbtest.asp",
    "getvpbxinfo.asp",
    "getvpbxinfo-dev.asp",
    "getvpbxinfo-defaultfiles.asp",
    "getvpbxinfo106.asp",
    "conferencelookup.asp",
    "conferencelookup-dev.asp",
    "getinboundlineinfov403.asp",
    "loglcrattempt.asp",
    "removemonitorid.asp",
    "smsnotificationqueue.asp",
    "synchtelcanvoip.asp",
    "synchtelcanvoipasync.asp",
    "voipcallmonitor.asp",
    "voipcalleridgetbyuserid.asp",
    "voipextinfoget.asp",
    "savecdrv5.asp",
    "savecdrv5-dev.asp",
    "xxxhandlecrm.asp",
}

_CDR_SKIP_FIELDS = {"ISMULTIREGNOS", "AUTOREGISTERTYPEID", "VIRTUALDID"}
_CDR_BOOLEAN_FIELDS = {"COSTFROMLEG1DUR", "CHARGELEG1"}
_CDR_NON_NUMERIC_FIELDS = {
    "RESELLERNO",
    "AGENTNO",
    "CLIENTNO",
    "LINENO",
    "LEG1TELNO",
    "LEG1START",
    "LEG1FINISH",
    "LEG1AREA",
    "LEG1VOICEPORT",
    "LEG1AREACODE",
    "LEG2TELNO",
    "LEG2START",
    "LEG2FINISH",
    "LEG2AREA",
    "LEG2VOICEPORT",
    "LEG2AREACODE",
    "VERSION",
    "CONNECTSTATUS",
    "COMMENTS",
    "INFODIGITS",
    "QUEUEAPPLICATION",
    "SURCHARGECOMMENTS",
    "PUBLICPIN",
    "LEG1STARTGMT",
    "LEG1FINISHGMT",
    "LEG2STARTGMT",
    "LEG2FINISHGMT",
    "RTLEG1NAME",
    "RTLEG2NAME",
    "LEG1RATECODE",
    "LEG2RATECODE",
}
_CDR_VALID_FIELDS = {
    token.strip("[]")
    for token in (
        "[ResellerID] [AgentID] [ClientID] [LineID] [ResellerNo] [AgentNo] [ClientNo] [LineNo] [Leg1TelNo] "
        "[Leg1Start] [Leg1Finish] [Leg1Duration] [Leg1Seconds] [Leg1RateID] [Leg1Rate] [Leg1Cost] [Leg1Area] "
        "[Leg1VoicePort] [Leg1AreaCode] [Leg2TelNo] [Leg2Start] [Leg2Finish] [Leg2Duration] [Leg2Seconds] "
        "[Leg2RateID] [Leg2Rate] [Leg2Cost] [Leg2Area] [Leg2VoicePort] [Leg2AreaCode] [BillingInterval] "
        "[ConnectionCharge] [RLeg1Duration] [RLeg1Rate] [RLeg1Cost] [RLeg2Duration] [RLeg2Rate] [RLeg2Cost] "
        "[RBillingInterval] [RConnectionCharge] [QueueID] [Web800CallID] [CDRTypeID] [Version] [Balance] [RBalance] "
        "[CostFromLeg1Dur] [ConnectStatus] [Cost] [Comments] [InfoDigits] [PayphoneCharge] [RPayphoneCharge] "
        "[PPayphoneCharge] [QueueApplication] [QueueTime] [RNetProfit] [PNetProfit] [Surcharges] [SurchargeComments] "
        "[ChargeLeg1] [Leg1ProviderID] [Leg2ProviderID] [PLeg1BillingInterval] [PLeg1Duration] [PLeg1Rate] "
        "[PLeg1Cost] [PLeg1NetProfit] [PLeg1ConnectionCharge] [PLeg2BillingInterval] [PLeg2Duration] [PLeg2Rate] "
        "[PLeg2Cost] [PLeg2NetProfit] [PLeg2ConnectionCharge] [PublicPIN] [ForcedConnectPeriod] [Leg1StartGMT] "
        "[Leg1FinishGMT] [Leg2StartGMT] [Leg2FinishGMT] [RtLeg1ID] [RtLeg2ID] [RtLeg1Name] [RtLeg2Name] "
        "[RateCategoryID] [RRateCategoryID] [Leg1RateCode] [Leg2RateCode] [ProductId] [VoiceMailId] [ExtNo] "
        "[MemoId] [RecordId]"
    ).split()
}

_ENDPOINT_DB_HINTS: dict[str, str] = {
    "servicetypeget.asp": "TelcanSwitch",
    "servicetypegetv2.asp": "TelcanSwitch",
    "inbounddidserveripget.asp": "TelcanSwitch",
    "switchconfiggetold.asp": "TelcanSwitch",
    "voipcallmonitor.asp": "TelcanSwitch/TelcanMonitor",
    "synchtelcanvoip.asp": "TelcanSwitch",
    "synchtelcanvoipasync.asp": "TelcanSwitch",
    "smsnotificationqueue.asp": "TelcanSwitch",
    "vmindicatorget.asp": "TelcanSwitch",
    "loglcrattempt.asp": "TelcanCalls_NYDB6",
    "savecdrv5.asp": "TelcanCalls_NYDB6/TelcanCalls/TelcanMonitor",
    "savecdrv5-dev.asp": "TelcanCalls_NYDB6/TelcanCalls/TelcanMonitor",
    "voipextinfoget.asp": "TelcanSwitch/TelcanInternet/TelcanMonitor",
    "voipcalleridgetbyuserid.asp": "TelcanInternet",
    "getinboundlineinfov403.asp": "TelcanSwitch/TelcanMonitor/TelcanInternet",
    "getinboundlineinfov405.asp": "TelcanSwitch/TelcanMonitor/TelcanInternet",
    "providerlookupv3.asp": "TelcanSwitch",
    "getratesv301.asp": "TelcanSwitch/TelcanCalls",
    "getratesv305.asp": "TelcanSwitch/TelcanCalls",
    "getratesv306.asp": "TelcanSwitch/TelcanCalls",
}


def _is_private_ip(ip_text: str) -> bool:
    try:
        return ipaddress.ip_address(ip_text).is_private
    except Exception:
        return False


def _discover_private_addr() -> str:
    # Prefer RFC1918/private addresses from local interfaces.
    for candidate in socket.gethostbyname_ex(socket.gethostname())[2]:
        if _is_private_ip(candidate):
            return candidate

    # Fallback to route-based detection.
    udp = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        udp.connect(("8.8.8.8", 80))
        candidate = udp.getsockname()[0]
        if _is_private_ip(candidate):
            return candidate
    except Exception:
        pass
    finally:
        udp.close()
    return ""

app = FastAPI(title=APP_NAME)
logger = logging.getLogger("vpbx-pybridge")
logging.basicConfig(level=os.getenv("VPBX_LOG_LEVEL", "INFO").upper())


def _list_asp_endpoints() -> set[str]:
    try:
        return {p.name for p in ASP_SOURCE_DIR.glob("*.asp")}
    except Exception:
        return set()


def _stringify_payload(data: object) -> object:
    if isinstance(data, dict):
        return {str(k): _stringify_payload(v) for k, v in data.items()}
    if isinstance(data, list):
        return [_stringify_payload(v) for v in data]
    if data is None:
        return ""
    if isinstance(data, bool):
        return "1" if data else "0"
    return str(data)


def _json_response(payload: dict[str, object], status_code: int = 200) -> JSONResponse:
    return JSONResponse(_stringify_payload(payload), status_code=status_code)


def _safe_sql_text(value: object) -> str:
    return str(value or "").replace("'", "''").strip()


def _is_int(value: object) -> bool:
    return bool(re.fullmatch(r"-?\d+", str(value or "").strip()))


def _to_int(value: object, default: int = 0) -> int:
    try:
        return int(str(value).strip())
    except Exception:
        return default


def _boolish(value: object) -> bool:
    if isinstance(value, bool):
        return value
    text = str(value or "").strip().lower()
    return text in {"1", "true", "yes", "on"}


def _get_local_addr(request: Request) -> str:
    forced = os.getenv("VPBX_LOCAL_ADDR", "").strip()
    if forced:
        return forced
    discovered = _discover_private_addr()
    if discovered:
        return discovered
    host = request.headers.get("host", "").strip()
    if host:
        host = host.split(":", 1)[0]
        if _is_private_ip(host):
            return host
    return "127.0.0.1"


def _private_base_url(request: Request) -> str:
    return f"http://{_get_local_addr(request)}:8091"


def _db_host(db_key: str) -> str:
    return os.getenv(f"VPBX_DB_HOST_{db_key}", DEFAULT_DB_HOST)


def _db_user(db_key: str) -> str:
    return os.getenv(f"VPBX_DB_USER_{db_key}", DEFAULT_DB_USER)


def _db_password(db_key: str) -> str:
    return os.getenv(f"VPBX_DB_PASSWORD_{db_key}", DEFAULT_DB_PASSWORD)


def _db_port(db_key: str) -> int:
    raw = os.getenv(f"VPBX_DB_PORT_{db_key}", str(DEFAULT_DB_PORT))
    try:
        return int(raw)
    except Exception:
        return DEFAULT_DB_PORT


def _db_mode(db_key: str) -> str:
    return os.getenv(f"VPBX_DB_MODE_{db_key}", DEFAULT_DB_MODE).strip().lower()


def _db_name(db_key: str) -> str:
    return DB_KEY_TO_DATABASE.get(db_key, db_key)


def _db_dsn(db_key: str) -> str:
    return os.getenv(f"VPBX_DSN_{db_key}", db_key)


def _connect(db_key: str):
    mode = _db_mode(db_key)
    if mode == "odbc":
        if pyodbc is None:
            raise RuntimeError("pyodbc is not installed in this environment")
        dsn = _db_dsn(db_key)
        uid = _db_user(db_key)
        pwd = _db_password(db_key)
        return pyodbc.connect(
            f"DSN={dsn};UID={uid};PWD={pwd}",
            timeout=DB_TIMEOUT_SECONDS,
            autocommit=True,
        )

    return pymssql.connect(
        server=_db_host(db_key),
        user=_db_user(db_key),
        password=_db_password(db_key),
        database=_db_name(db_key),
        port=_db_port(db_key),
        login_timeout=DB_TIMEOUT_SECONDS,
        timeout=DB_TIMEOUT_SECONDS,
        as_dict=True,
    )


def _fetch_all(sql: str, db_key: str) -> list[dict[str, Any]]:
    logger.debug("DB[%s] SQL=%s", db_key, sql)
    with _connect(db_key) as conn:
        mode = _db_mode(db_key)
        if mode == "odbc":
            cur = conn.cursor()
            cur.execute(sql)
            if cur.description is None:
                return []
            cols = [str(c[0]) for c in cur.description]
            return [dict(zip(cols, row)) for row in cur.fetchall()]

        cur = conn.cursor(as_dict=True)
        cur.execute(sql)
        rows = cur.fetchall()
        return rows or []


def _fetch_one(sql: str, db_key: str) -> dict[str, Any] | None:
    rows = _fetch_all(sql, db_key)
    return rows[0] if rows else None


def _execute(sql: str, db_key: str) -> int:
    logger.debug("DB[%s] EXEC=%s", db_key, sql)
    with _connect(db_key) as conn:
        mode = _db_mode(db_key)
        if mode == "odbc":
            cur = conn.cursor()
            cur.execute(sql)
            return int(cur.rowcount or 0)

        cur = conn.cursor(as_dict=True)
        cur.execute(sql)
        return int(cur.rowcount or 0)


def _looks_like_db_unavailable(exc_text: str) -> bool:
    text = (exc_text or "").lower()
    markers = [
        "database '",
        "login failed for user",
        "adaptive server connection failed",
        "unable to connect: adaptive server is unavailable",
        "in the middle of a restore",
        "has been marked suspect",
        "currently not accessible for queries",
        "not enabled for read access",
        "connection refused",
        "db-lib error message 20002",
        "db-lib error message 20009",
    ]
    return any(m in text for m in markers)


def _extract_db_name_from_error(exc_text: str) -> str:
    text = str(exc_text or "")
    m = re.search(r"Database '([^']+)'", text, flags=re.IGNORECASE)
    return m.group(1) if m else ""


def _db_error(endpoint: str, exc: Exception) -> JSONResponse:
    exc_text = str(exc)
    endpoint_l = str(endpoint or "").casefold()
    if AVAILABLE_ONLY_MODE and _looks_like_db_unavailable(exc_text):
        db_name = _extract_db_name_from_error(exc_text)
        payload: dict[str, Any] = {
            "ResultID": -9,
            "Status": "degraded",
            "Error": "Endpoint temporarily unavailable in available-only mode",
            "Endpoint": endpoint,
            "Mode": "available-only",
            "Message": "This endpoint depends on a database that is currently unavailable.",
        }
        if db_name:
            payload["Database"] = db_name
        db_hint = _ENDPOINT_DB_HINTS.get(endpoint_l, "")
        if db_hint and db_hint != db_name:
            payload["DatabaseHint"] = db_hint
        logger.warning(
            "Endpoint %s unavailable in available-only mode: %s",
            endpoint,
            exc_text[:300],
        )
        return _json_response(payload, status_code=200)

    logger.exception("Endpoint %s failed", endpoint)
    return _json_response(
        {
            "ResultID": -2,
            "Error": "DB connection/query failed",
            "Endpoint": endpoint,
            "Details": exc_text,
        },
        status_code=500,
    )


GENERIC_PROC_DB_CANDIDATES: tuple[str, ...] = (
    "TelcanAccounts",
    "TelcanSwitch",
    "TelcanLCR",
    "TelcanCalls",
    "TelcanMonitor",
    "TelcanInternet",
    "TelcanQueue",
)


def _normalized_proc_params(request: Request) -> dict[str, str]:
    params: dict[str, str] = {}
    for key, value in request.query_params.items():
        clean_key = re.sub(r"[^0-9A-Za-z_]", "", str(key or ""))
        if not clean_key:
            continue
        params[clean_key] = str(value or "")
    return params


def _build_exec_proc_sql(proc_name: str, params: dict[str, str]) -> str:
    if not params:
        return f"EXEC [dbo].[{proc_name}]"
    pieces = [f"@{k}=N'{_safe_sql_text(v)}'" for k, v in params.items()]
    return f"EXEC [dbo].[{proc_name}] " + ", ".join(pieces)


def _try_generic_proc_endpoint(endpoint: str, request: Request) -> dict[str, Any]:
    base = re.sub(r"[^0-9A-Za-z_]", "", (endpoint or "").rsplit(".", 1)[0].strip())
    if not base:
        return {
            "ResultID": -1,
            "Endpoint": endpoint,
            "Error": "Invalid endpoint name",
            "Mode": "generic-proc",
        }

    params = _normalized_proc_params(request)
    proc_candidates = [f"usp_{base}", f"sp{base}", base]
    attempts: list[str] = []
    errors: list[str] = []

    for db_key in GENERIC_PROC_DB_CANDIDATES:
        for proc_name in proc_candidates:
            sql = _build_exec_proc_sql(proc_name, params)
            attempts.append(f"{db_key}:{proc_name}")
            try:
                row = _fetch_one(sql, db_key)
                if row:
                    payload: dict[str, Any] = {
                        "ResultID": 1,
                        "Endpoint": endpoint,
                        "Mode": "generic-proc",
                        "DBKey": db_key,
                        "Procedure": proc_name,
                    }
                    payload.update(row)
                    return payload
                # Some procedures return no row but still complete successfully.
                _execute(sql, db_key)
                return {
                    "ResultID": 1,
                    "Endpoint": endpoint,
                    "Mode": "generic-proc",
                    "DBKey": db_key,
                    "Procedure": proc_name,
                    "Message": "Executed successfully with no row payload",
                }
            except Exception as exc:
                errors.append(f"{db_key}:{proc_name}: {str(exc)[:200]}")
                continue

    return {
        "ResultID": -1,
        "Endpoint": endpoint,
        "Mode": "generic-proc",
        "Error": "Endpoint not migrated yet and generic proc lookup failed",
        "Tried": attempts[:30],
        "Details": errors[:10],
    }


def _param(request: Request, key: str, default: str = "") -> str:
    value = request.query_params.get(key)
    if value is not None:
        return str(value)
    key_l = key.casefold()
    for k, v in request.query_params.items():
        if str(k).casefold() == key_l:
            return str(v)
    return default


def _decode_param(value: str) -> str:
    return unquote_plus(value or "")


def _keep_only_chars(value: str, allowed: str) -> str:
    allowed_set = set(allowed)
    return "".join(ch for ch in (value or "") if ch in allowed_set)


def _is_number(value: object) -> bool:
    return bool(re.fullmatch(r"-?\d+(\.\d+)?", str(value or "").strip()))


def _first_row_value(row: dict[str, Any] | None, default: Any = "") -> Any:
    if not row:
        return default
    for _, v in row.items():
        return v
    return default


def _callerid_value(result_text: str) -> str:
    text = str(result_text or "").strip()
    if text.casefold().startswith("callerid="):
        return text.split("=", 1)[1]
    return text


def _strip_sound_name(raw: object) -> str:
    text = str(raw or "").replace("\\", "/")
    base = text.rsplit("/", 1)[-1]
    if base.lower().endswith(".wav"):
        base = base[:-4]
    return base


def _fix_ring_to_number(ring_to_number: str, sip_forward: str = "") -> str:
    number = (ring_to_number or "").strip()
    if number in {"", "0"}:
        return f"Sip/{sip_forward}@64.34.222.236" if sip_forward.strip() else ""

    if "Skype" in number:
        return number.replace("Skype/", "Sip/") + "@64.34.222.240"

    if "Sip" in number:
        return number

    number = re.sub(r"[\-\)\(\.\s]", "", number)
    if len(number) == 10 and not number.startswith(("1", "011", "00")):
        return f"1{number}"
    if number.startswith("1"):
        return number[:11]
    if number.startswith("00"):
        return f"011{number[2:]}"
    if not number.startswith("011"):
        return f"011{number}"
    return number


def _get_extension_prompts(line_no: str, ext_no: str, connect_type: str) -> dict[str, str]:
    sql = (
        " Select IsNull(MenuItemID, -1) AS MenuItemID, "
        " WavSoundFileName = Case PT.PromptTypeID "
        " When 1 Then IsNUll(Replace( SUBSTRING ( WavSoundFileName , (Len(WavSoundFileName) + 2 )-  CHARINDEX ( '\\\\', REVERSE ( WavSoundFileName ) ) , Len(WavSoundFileName) ), '.wav',''), 'jazz1') "
        " When 2 Then IsNUll(Replace( SUBSTRING ( WavSoundFileName , (Len(WavSoundFileName) + 2 )-  CHARINDEX ( '\\\\', REVERSE ( WavSoundFileName ) ) , Len(WavSoundFileName) ), '.wav',''), 'vmail') "
        " When 6 Then IsNUll(Replace( SUBSTRING ( WavSoundFileName , (Len(WavSoundFileName) + 2 )-  CHARINDEX ( '\\\\', REVERSE ( WavSoundFileName ) ) , Len(WavSoundFileName) ), '.wav',''), '') "
        " When 10 Then IsNUll(Replace( SUBSTRING ( WavSoundFileName , (Len(WavSoundFileName) + 2 )-  CHARINDEX ( '\\\\', REVERSE ( WavSoundFileName ) ) , Len(WavSoundFileName) ), '.wav',''), 'fax') End, "
        " PT.PromptTypeID AS PromptTypeID "
        " FROM VPBXPromptTypes PT WITH (NOLOCK) "
        " LEFT JOIN VPBXMEnuItems MI WITH (NOLOCK) ON PT.PromptTypeID = MI.PromptTypeID "
        f" AND [LineNO] = '{_safe_sql_text(line_no)}' AND ExtNo = '{_safe_sql_text(ext_no)}' "
        " WHERE PT.PromptTypeID IN (1,2,6,10)"
    )
    rows = _fetch_all(sql, "TelcanAccounts")
    out: dict[str, str] = {}
    for row in rows:
        pt = _to_int(row.get("PromptTypeID"), -1)
        wav = str(row.get("WavSoundFileName") or "")
        menu_id = _to_int(row.get("MenuItemID"), -1)
        if pt == 1:
            if str(connect_type) == "5":
                out["MusicOnHold"] = wav.replace("ring", "jazz6")
            else:
                out["MusicOnHold"] = wav.replace("ring", "-1")
            out["MusicTimeOut"] = "0"
            out["MusicTimeOutPrompt"] = "0"
        elif pt == 2:
            out["VoiceMailPromptID"] = str(menu_id if menu_id >= 0 else wav)
        elif pt == 6:
            out["ExtNameID"] = wav
        elif pt == 10:
            out["FaxOnDemand"] = wav
    return out


def _proc_vpbx(line_no: str, queue_id: int, ani: str, ext_no: str) -> dict[str, Any]:
    line_sql = (
        " Select Lines.[LineNo], IsNull(Lines.CallHunt,0) AS CallHunt, IsNull(Lines.VirtualPBX,0) AS VirtualPBX, "
        " IsNull(Lines.F_VPBX,0) AS F_VPBX, IsNull(Lines.F_CallHunt,0) AS F_CallHunt, IsNull(Lines.F_VMail,0) AS F_VMail, "
        " IsNull(Lines.VoiceMail,0) AS VoiceMail, IsNull(F_Recording,0) AS F_Recording, IsNUll(Recording,0) AS Recording, "
        " IsNUll(F_Memo,0) AS F_Memo, IsNull(Memo,0) AS Memo, IsNUll(CallBackNo,'') AS RingToNumber, PINRequired, PublicPIN, IsNull([CallTypeAutoDigits],'') AS ExtDigits "
        " , IsNull(VoicemailDuration, 60) AS VoicemailDuration, IsNull(VoicemailSize, 0) AS VoicemailSize "
        " FROM Lines WITH (NOLOCK) LEFT JOIN LineFeatures WITH (NOLOCK) ON LineFeatures.[LineNo] = Lines.[LineNO] "
        f" WHERE Lines.[LineNo] = {_safe_sql_text(line_no)}"
    )
    line_row = _fetch_one(line_sql, "TelcanAccounts")
    if not line_row:
        return {"ResultID": -1, "Error": "Line not found", "LineNo": line_no}

    voice_mail = _to_int(line_row.get("VoiceMail"), 0)
    voice_mail_disabled = voice_mail <= 0
    is_voice_mail_forced = (voice_mail == 2) and (not voice_mail_disabled)

    if _boolish(line_row.get("VirtualPBX")) and _to_int(line_row.get("F_VPBX"), 0) > 0:
        vpbx_enabled = True
        call_hunt_enabled = False
    else:
        vpbx_enabled = False
        call_hunt_enabled = _boolish(line_row.get("CallHunt")) and _to_int(line_row.get("F_CallHunt"), 0) > 0

    if vpbx_enabled:
        is_voice_mail_forced = False

    if _to_int(line_row.get("F_Recording"), 0) > 0:
        recording_enabled = _to_int(line_row.get("Recording"), 0)
    else:
        recording_enabled = 0

    ring_to_number = str(line_row.get("RingToNumber") or "")
    ext_digits = str(line_row.get("ExtDigits") or "")
    pin_required = _to_int(line_row.get("PINRequired"), 0)
    public_pin = str(line_row.get("PublicPIN") or "")
    voicemail_size = _to_int(line_row.get("VoicemailSize"), 0)
    voicemail_duration = _to_int(line_row.get("VoicemailDuration"), 60)

    count_sql = (
        "Select Count(*) AS VoiceMailCount from VoiceMail Where msgStatus <> 'DELETED' "
        "AND VMailStatus <> 0 AND VPBXExtNo='-1' "
        f"AND [LineNO] = {_safe_sql_text(line_no)}"
    )
    vm_count_row = _fetch_one(count_sql, "TelcanAccounts") or {}
    available_vm = voicemail_size - _to_int(vm_count_row.get("VoiceMailCount"), 0)
    if available_vm < 0:
        available_vm = 0

    extension_length = 3
    max_tries = 1
    term_digits = "#"
    operator_extension = "0"
    start_menu_item_id = 1

    if vpbx_enabled:
        vpbx_row = _fetch_one(
            f"SELECT * FROM VPBX WITH (NOLOCK) where [LineNo]='{_safe_sql_text(line_no)}'",
            "TelcanAccounts",
        )
        if vpbx_row:
            start_menu_item_id = _to_int(vpbx_row.get("StartMenuItemID"), 1)

            rules_sql = (
                f"EXEC spVPBX_CheckRules @LineNo='{_safe_sql_text(line_no)}', "
                f"@MenuItemID={start_menu_item_id}, @QueueID={queue_id}, @ANI='{_safe_sql_text(ani)}'"
            )
            rules_row = _fetch_one(rules_sql, "TelcanAccounts")
            tmp_ring = ring_to_number
            if rules_row:
                start_menu_item_id = _to_int(rules_row.get("MenuItemID"), start_menu_item_id)
                tmp_ring = str(rules_row.get("RingToNo") or "").strip() or ring_to_number

            if start_menu_item_id > 90:
                vpbx_enabled = True
                call_hunt_enabled = False
                ring_to_number = ""
            else:
                if len(tmp_ring.strip()) == 0:
                    vpbx_enabled = True
                    call_hunt_enabled = False
                    ring_to_number = ""
                elif len(tmp_ring.strip()) <= 5:
                    vpbx_enabled = True
                    call_hunt_enabled = False
                    ring_to_number = tmp_ring.strip()
                else:
                    vpbx_enabled = False
                    call_hunt_enabled = False
                    ring_to_number = tmp_ring.strip()

            extension_length = _to_int(vpbx_row.get("ExtensionLength"), 3)
            max_tries = _to_int(vpbx_row.get("MaxTries"), 1)
            term_digits = str(vpbx_row.get("TermDigits") or "#")
            operator_extension = str(vpbx_row.get("OperatorExtension") or "0").strip() or "0"
        else:
            vpbx_enabled = False

    if (not vpbx_enabled) and is_voice_mail_forced:
        ring_to_number = "VMAIL"

    payload: dict[str, Any] = {
        "ResultID": 1,
        "LineNo": line_no,
        "VPBXEnabled": int(vpbx_enabled),
        "HuntType": "1" if call_hunt_enabled else "0",
        "CallRecording": recording_enabled,
        "ExtensionLength": extension_length,
        "StartMenuItemID": start_menu_item_id,
        "MaxTries": max_tries,
        "TermDigits": term_digits,
        "OperatorExtension": operator_extension,
        "RingToNo": _fix_ring_to_number(ring_to_number, ""),
        "ExtDigits": ext_digits,
        "PINRequired": pin_required,
        "PublicPIN": public_pin,
        "VoiceMail": voice_mail,
        "VoicemailSize": voicemail_size,
        "AvailableVoiceMail": available_vm,
        "VoicemailDuration": voicemail_duration,
    }
    return payload


def _proc_call_hunt(line_no: str, ext_no: str) -> dict[str, Any]:
    ext_for_proc = ext_no if ext_no and _is_int(ext_no) else "-1"
    sql = f"EXEC spGetCallHuntInfo @LineNo={_safe_sql_text(line_no)}, @VPBXExtension={_safe_sql_text(ext_for_proc)}"
    rows = _fetch_all(sql, "TelcanAccounts")

    out_rows: list[dict[str, Any]] = []
    if rows:
        for row in rows:
            out_rows.append(
                {
                    "VPBXExtension": row.get("VPBXExtension"),
                    "HuntGroup": row.get("HuntGroup"),
                    "HuntNos": _fix_ring_to_number(str(row.get("HuntNos") or ""), ""),
                    "HuntGroupTimeout": row.get("HuntGroupTimeout"),
                }
            )
    else:
        fallback_sql = (
            "Select ExtNo, RingToNo FROM TelcanAccounts.dbo.VPBXExts WITH (NOLOCK) "
            f"Where [LineNo] = {_safe_sql_text(line_no)} AND ExtNo='{_safe_sql_text(ext_for_proc)}' AND VoiceMail = 1"
        )
        fallback_row = _fetch_one(fallback_sql, "TelcanAccounts")
        if fallback_row:
            out_rows.append(
                {
                    "VPBXExtension": ext_for_proc,
                    "HuntGroup": 1,
                    "HuntNos": _fix_ring_to_number(str(fallback_row.get("RingToNo", "")), ""),
                    "HuntGroupTimeout": 15,
                }
            )
        else:
            out_rows.append(
                {
                    "VPBXExtension": ext_for_proc,
                    "HuntGroup": 1,
                    "HuntNos": "VMAIL",
                    "HuntGroupTimeout": 15,
                }
            )

    return {"ResultID": 1, "Rows": out_rows}


def _proc_vpbx_extensions(line_no: str, queue_id: int, ext_no: str) -> dict[str, Any]:
    sql = f"EXEC spVPBX_GetExtensions @LineNo='{_safe_sql_text(line_no)}', @ApplyRules=0, @QueueID={queue_id}"
    if ext_no:
        sql += f", @ExtNo='{_safe_sql_text(ext_no)}'"

    rows = _fetch_all(sql, "TelcanAccounts")
    if not rows:
        return {"ResultID": -1, "Rows": []}

    out_rows: list[dict[str, Any]] = []
    for row in rows:
        hunt_type = str(row.get("HuntType") or "")
        ring_to = str(row.get("RingToNo") or "")

        if hunt_type == "5":
            if "Sip" not in ring_to:
                ring_to = f"Sip/{ring_to}@64.34.222.236"
        elif hunt_type == "6":
            if "Skype" not in ring_to:
                ring_to = ring_to.replace("Skype/", "Sip/") + "@64.34.222.240"
        elif hunt_type == "7":
            if "Sip" not in ring_to:
                ring_to = f"Sip/{ring_to}@64.34.222.236"
        else:
            ring_to = _fix_ring_to_number(ring_to, "")

        ext = str(row.get("ExtNo") or "")
        item: dict[str, Any] = {
            "LineNo": row.get("LineNo"),
            "ExtNo": ext,
            "FirstName": row.get("FirstName"),
            "LastName": row.get("LastName"),
            "RingToNo": ring_to,
            "PIN": row.get("PIN"),
            "VoiceMail": row.get("VoiceMail"),
            "ConnectTimeout": row.get("ConnectTimeout"),
            "ConnectType": row.get("ConnectType"),
            "HuntID": row.get("HuntID"),
            "PBXConnectDigits": row.get("PBXConnectDigits"),
            "FullRecording": row.get("bFullRecording"),
            "MemoRecording": row.get("bMemoRecording"),
            "Paging": row.get("Paging"),
        }
        out_rows.append(item)

    return {"ResultID": 1, "Rows": out_rows}


async def _fire_and_forget(target_url: str) -> None:
    try:
        async with httpx.AsyncClient(timeout=5.0) as client:
            await client.post(target_url)
    except Exception:
        pass


async def _handle_test(_: Request, endpoint: str, __: BackgroundTasks) -> JSONResponse:
    try:
        row = _fetch_one("SELECT COUNT(*) AS RecCount FROM ClientDevices", "TelcanAccounts") or {}
        return _json_response({"ResultID": 1, "Endpoint": endpoint, "RecCount": row.get("RecCount", 0)})
    except Exception as exc:
        return _db_error(endpoint, exc)


async def _handle_service_type(request: Request, endpoint: str, _: BackgroundTasks, v2_logic: bool) -> JSONResponse:
    try:
        api_v = (request.query_params.get("v") or "2").strip()
        dnis = (request.query_params.get("DNIS") or "").strip()
        if (not dnis) or (not _is_int(dnis)) or len(dnis) > 19:
            return _json_response({"ResultID": 0, "Endpoint": endpoint})

        local_addr = _get_local_addr(request)
        proc_name = "usps_InboundDID_Get" if api_v == "1" else "usp_ServiceTypeGet"
        sql = (
            f"EXEC [dbo].[{proc_name}] @DNIS = N'{_safe_sql_text(dnis)}',"
            f"@ANI = N'',@ServerIP = N'{_safe_sql_text(local_addr)}',@ProviderIP = N'{_safe_sql_text(local_addr)}'"
        )
        row = _fetch_one(sql, "TelcanSwitch")

        if not row:
            return _json_response({"ResultID": 0, "Endpoint": endpoint})

        if api_v == "1":
            result = _to_int(row.get("LineTypeID"), 0)
        else:
            result = _to_int(row.get("ServiceTypeID"), 0)
            if v2_logic and result == 0:
                dnis_10 = dnis
                if len(dnis_10) == 11 and dnis_10.startswith("1"):
                    dnis_10 = dnis_10[1:]
                area = dnis_10[:3]
                tollfree = {"800", "833", "844", "855", "866", "877", "888"}
                canada_int = {
                    "204", "226", "236", "249", "250", "263", "289", "306", "343", "354", "365", "367", "368", "403", "416",
                    "418", "428", "431", "437", "438", "450", "468", "474", "506", "514", "519", "548", "579", "581", "584", "587",
                    "604", "613", "639", "647", "672", "683", "705", "709", "742", "753", "778", "780", "782", "807", "819", "825",
                    "867", "873", "879", "902", "905", "011",
                }
                if area in tollfree:
                    result = 1
                elif area in canada_int:
                    result = 0
                else:
                    result = 1

        return _json_response({"ResultID": result, "Endpoint": endpoint})
    except Exception as exc:
        return _db_error(endpoint, exc)


async def _handle_service_type_get(request: Request, endpoint: str, bg: BackgroundTasks) -> JSONResponse:
    return await _handle_service_type(request, endpoint, bg, v2_logic=False)


async def _handle_service_type_get_v2(request: Request, endpoint: str, bg: BackgroundTasks) -> JSONResponse:
    return await _handle_service_type(request, endpoint, bg, v2_logic=True)


async def _handle_inbound_did_server_ip_get(request: Request, endpoint: str, _: BackgroundTasks) -> JSONResponse:
    try:
        dnis = (request.query_params.get("DNIS") or "").strip()
        if (not dnis) or (not _is_int(dnis)) or len(dnis) > 19:
            return _json_response({"ResultID": 0, "ServerIP": 0, "Endpoint": endpoint})

        local_addr = _get_local_addr(request)
        sql = (
            " EXEC [dbo].[usps_InboundDID_ServerIP_Get] "
            f"@DNIS = N'{_safe_sql_text(dnis)}',@ANI = N'',"
            f"@ServerIP = N'{_safe_sql_text(local_addr)}',@ProviderIP = N'{_safe_sql_text(local_addr)}'"
        )
        row = _fetch_one(sql, "TelcanSwitch")
        server_ip = str((row or {}).get("ServerIP") or "0")
        return _json_response({"ResultID": server_ip, "ServerIP": server_ip, "Endpoint": endpoint})
    except Exception as exc:
        return _db_error(endpoint, exc)


async def _handle_get_line_no_count(request: Request, endpoint: str, _: BackgroundTasks) -> JSONResponse:
    try:
        line_no = _param(request, "LineNo").strip()
        if not line_no:
            return _json_response({"ResultID": -1})
        if not _is_int(line_no):
            return _json_response({"ResultID": -1, "Error": "LineNo must be numeric"})

        row = _fetch_one(f"EXECUTE spMon_GetLineNoCount_Dev {_safe_sql_text(line_no)}", "TelcanMonitor")
        if not row:
            return _json_response({"ResultID": -1})
        return _json_response(row)
    except Exception as exc:
        return _db_error(endpoint, exc)


async def _handle_voip_db_test(request: Request, endpoint: str, _: BackgroundTasks) -> JSONResponse:
    db_name = (request.query_params.get("DBName") or "").strip()
    query = "EXEC usp_DBTest"
    db_key = "TelcanAccounts"

    if db_name == "DBS1":
        db_key = "TelcanAccounts"
    elif db_name == "DBS2":
        db_key = "TelcanCalls"
    elif db_name in {"DBS4", "GDBS10", "LA-NAS1"}:
        db_key = "TelcanMonitor"
    elif db_name in {"GREG1", "la-dbs1"}:
        return _json_response(
            {
                "ResultID": -3,
                "Endpoint": endpoint,
                "Error": "MySQL mode for this endpoint is not configured yet",
                "DBName": db_name,
            },
            status_code=200,
        )

    try:
        row = _fetch_one(query, db_key) or {}
        rec_count = row.get("rec_count")
        if rec_count is None:
            rec_count = row.get("RecCount", 0)
        return _json_response({"ResultID": 1, "Endpoint": endpoint, "DBName": db_name, "rec_count": rec_count})
    except Exception as exc:
        return _db_error(endpoint, exc)


async def _handle_get_vpbx_info(request: Request, endpoint: str, _: BackgroundTasks) -> JSONResponse:
    line_no = (request.query_params.get("LineNo") or "").strip()
    proc = (request.query_params.get("PROC") or "").strip().upper()
    ext_no = (request.query_params.get("EXT") or "").strip()
    ani = (request.query_params.get("ANI") or "").strip()
    queue_raw = (request.query_params.get("QueueID") or "").strip()
    queue_id = _to_int(queue_raw, 0)

    if not line_no:
        return _json_response({"ResultID": -1, "Error": "LineNo is required", "Endpoint": endpoint})

    try:
        if proc == "VPBX":
            return _json_response(_proc_vpbx(line_no, queue_id, ani, ext_no))
        if proc == "CALLHUNT":
            return _json_response(_proc_call_hunt(line_no, ext_no))
        if proc == "VPBXEXTENSIONS":
            return _json_response(_proc_vpbx_extensions(line_no, queue_id, ext_no))

        return _json_response(
            {
                "ResultID": -1,
                "Endpoint": endpoint,
                "Error": "PROC not migrated yet",
                "PROC": proc,
                "SupportedPROC": ["VPBX", "CALLHUNT", "VPBXEXTENSIONS"],
            },
            status_code=200,
        )
    except Exception as exc:
        return _db_error(endpoint, exc)


async def _handle_get_caller_id_v3(request: Request, endpoint: str, _: BackgroundTasks) -> JSONResponse:
    try:
        valid_number_input = "0123456789_"

        ani = _decode_param(_param(request, "ANI")).strip()
        if ani.casefold() != "anonymous":
            ani = _keep_only_chars(ani, valid_number_input)

        dnis = _keep_only_chars(_decode_param(_param(request, "DNIS")).strip(), valid_number_input)
        line_no = _keep_only_chars(_decode_param(_param(request, "LineNo")).strip(), valid_number_input)
        is_provider = _keep_only_chars(_decode_param(_param(request, "IsProvider")).strip(), valid_number_input)
        caller_name = _decode_param(_param(request, "CallerName")).strip().replace("'", "")
        lcr = _param(request, "LCR").strip()

        if is_provider not in {"1", "3"}:
            is_provider = "0"

        if len(ani.strip()) > 10 and not ani.startswith(("1", "0", "+")) and "_" not in ani:
            ani = f"+{ani}"

        result_text = ""
        if ani:
            sql = (
                " EXEC [dbo].[usp_GetCallerIDV33] "
                f"@ANI='{_safe_sql_text(ani)}', @DNIS='{_safe_sql_text(dnis)}', "
                f"@LineNo='{_safe_sql_text(line_no)}', @IsProvider={_safe_sql_text(is_provider)}, "
                f"@CallerName='{_safe_sql_text(caller_name)}' "
            )
            row = _fetch_one(sql, "TelcanAccounts")
            if row:
                result_text = f"CallerID={row.get('CallerID', '')}"
            else:
                result_text = f"CallerID={ani}"

        result_text = result_text.replace('"', "")

        if not result_text.strip():
            if ani and not line_no:
                result_text = f"CallerID={ani}"
            else:
                result_text = "CallerID=Anonymous"

        if result_text in {"CallerID=<UNKNOWN>", "CallerID=<Anonymous>", "CallerID=Anonymous"} and lcr == "11":
            caller_id = ""
            if len(line_no) == 10:
                caller_id = "1"
            caller_id = f"{caller_id}{line_no}"
            result_text = f"CallerID={caller_id}"

        return _json_response({"CallerID": _callerid_value(result_text)})
    except Exception as exc:
        return _db_error(endpoint, exc)


async def _handle_set_busy2(request: Request, endpoint: str, _: BackgroundTasks) -> JSONResponse:
    try:
        application_type_id = 6
        computer_name = _param(request, "ComputerName").strip()
        port_id = _param(request, "PortID").strip()
        message = _param(request, "Message").strip()
        line_no = _param(request, "LineNo").strip()
        provider_id = _param(request, "ProviderID").strip()
        queue_id = _param(request, "QueueID").strip()

        dnis = _param(request, "DNIS").strip()
        ani = _param(request, "ANI").strip()
        extension = _param(request, "Extension").strip()
        clinet_no = _param(request, "ClinetNo").strip()
        reseller_no = _param(request, "ResellerNo").strip()
        peer_ip = _param(request, "peerip").strip()
        switch_ip = _param(request, "IPAddress").strip()
        direction = _param(request, "Direction").strip()
        charge_to_be = _param(request, "Amount").strip()
        leg2_tel_no = _param(request, "RingToNum").strip()

        if not _is_number(charge_to_be):
            charge_to_be = "0"

        if direction != "1":
            direction = "0"

        if not computer_name or not port_id or not line_no:
            return _json_response({"ResultID": -1, "MonitorID": ""})

        line_no_sql = _safe_sql_text(line_no)
        if _is_int(line_no_sql):
            line_no_expr = line_no_sql
        else:
            line_no_expr = f"'{line_no_sql}'"

        monitor_sql = (
            "EXECUTE spMon_GetMonitorID "
            f"@ApplicationTypeID={application_type_id},"
            f"@ComputerName='{_safe_sql_text(computer_name)}',"
            f"@ApplicationName='{_safe_sql_text(port_id)}',"
            f"@LineNo={line_no_expr}"
        )
        monitor_row = _fetch_one(monitor_sql, "TelcanMonitor")
        monitor_id = str((monitor_row or {}).get("MonitorID") or "").strip()

        if not monitor_id:
            return _json_response({"ResultID": -2, "MonitorID": ""})

        line_no_norm = line_no
        if len(line_no_norm) >= 11:
            if line_no_norm.startswith("8888988"):
                line_no_norm = line_no_norm[7:]
            if line_no_norm.startswith("1") and len(line_no_norm) == 11:
                line_no_norm = line_no_norm[1:]

        if not provider_id and _is_int(line_no_norm) and len(line_no_norm) > 7:
            row = _fetch_one(
                f"SELECT ProviderID FROM TelcanAccounts.dbo.Lines WITH (NOLOCK) WHERE [LineNo]={_safe_sql_text(line_no_norm)}",
                "TelcanAccounts",
            )
            if row:
                provider_id = str(row.get("ProviderID") or "").strip()

        line_no_expr = line_no_norm if _is_int(line_no_norm) else f"'{_safe_sql_text(line_no_norm)}'"
        set_busy_sql = (
            f"EXECUTE spMon_SetBusy_dev @MonitorID={_safe_sql_text(monitor_id)},"
            f"@Message='{_safe_sql_text(message)}', @LineNo={line_no_expr}"
        )
        if provider_id and _is_int(provider_id):
            set_busy_sql += f", @ProviderID={_safe_sql_text(provider_id)}"

        set_busy_sql += (
            f", @DNIS = '{_safe_sql_text(dnis)}'"
            f", @ClinetNo = '{_safe_sql_text(clinet_no)}'"
            f", @ResellerNo = '{_safe_sql_text(reseller_no)}'"
            f", @ANI = '{_safe_sql_text(ani)}'"
            f", @Ext = '{_safe_sql_text(extension)}'"
            f", @PeerIP = '{_safe_sql_text(peer_ip)}'"
            f", @SwitchIP = '{_safe_sql_text(switch_ip)}'"
            f", @Direction = {_safe_sql_text(direction)}"
            f", @ChargeToBe = {_safe_sql_text(charge_to_be)}"
            f", @Leg2TelNo = '{_safe_sql_text(leg2_tel_no)}'"
        )
        if queue_id and _is_int(queue_id):
            set_busy_sql += f", @QueueID={_safe_sql_text(queue_id)}"

        _execute(set_busy_sql, "TelcanMonitor")
        return _json_response({"ResultID": 1, "MonitorID": monitor_id})
    except Exception as exc:
        return _db_error(endpoint, exc)


async def _handle_fax_status_v2(request: Request, endpoint: str, _: BackgroundTasks) -> JSONResponse:
    try:
        fax_id = _param(request, "FaxId").strip()
        line_no = _param(request, "LineNo").strip()
        status_txt = _param(request, "Status").strip()
        status_id = _to_int(status_txt, -1) if _is_int(status_txt) else -1
        queue_id = _param(request, "QueueID").strip()
        queue_id = queue_id if _is_int(queue_id) else "0"

        comments = _decode_param(_param(request, "Comments").strip())
        if _is_int(comments):
            status_row = _fetch_one(
                f"SELECT ErrorStatusName FROM FaxStatuses WITH (NOLOCK) WHERE StatusID = {_safe_sql_text(comments)}",
                "TelcanAccounts",
            )
            if status_row and status_row.get("ErrorStatusName") is not None:
                comments = str(status_row.get("ErrorStatusName"))

        page_count = _param(request, "PageCount").strip()
        fax_rate = _param(request, "FaxRate").strip()
        resolution = _param(request, "Resolution").strip()
        image_size = _param(request, "ImageSize").strip()

        if status_id == 12 and not page_count:
            for part in comments.split("|"):
                compact = part.replace(" ", "")
                if compact[:9].upper() == "PAGECOUNT":
                    parts = compact.split("=", 1)
                    if len(parts) == 2:
                        page_count = parts[1]
                        break

        if line_no == "":
            return _json_response({"ResultId": 0, "ResultStr": "FaxId and LineNo are required values and are missing"})
        if status_id == -1:
            return _json_response({"ResultId": 0, "ResultStr": "Status is a required field and is missing"})
        if not (_is_int(fax_id) and _is_int(line_no)):
            return _json_response({"ResultId": 0, "ResultStr": "Invalid information provided"})
        if status_id > 12:
            return _json_response({"ResultId": 0, "ResultStr": "Invalid status value"})

        rs = _fetch_all(
            f"SELECT * FROM FaxQueue WITH (NOLOCK) WHERE FaxId = {_safe_sql_text(fax_id)} AND [LineNo] = {_safe_sql_text(line_no)}",
            "TelcanAccounts",
        )
        if len(rs) != 1:
            return _json_response({"ResultId": 0, "ResultStr": "Invalid information provided"})

        if not _is_int(page_count):
            page_count = "0"
        if not _is_int(fax_rate):
            fax_rate = "0"
        if len(resolution) > 14:
            resolution = resolution[:15]
        if not _is_int(image_size):
            image_size = "0"

        update_sql = (
            "UPDATE FaxQueue SET [Status] = ISNULL((Select TOP 1 FS.StatusName FROM FaxStatuses FS WITH (NOLOCK) "
            f"WHERE FS.StatusID = {status_id}),''), "
            f"[Comments]='{_safe_sql_text(comments)}', UpdateTime = GetDate(), GMTUpdateTime=GETUTCDATE(), "
            f"StatusID = {status_id}, PageCount={_safe_sql_text(page_count)}, FaxRate={_safe_sql_text(fax_rate)}, "
            f"Resolution='{_safe_sql_text(resolution)}', ImageSize={_safe_sql_text(image_size)} "
            f"WHERE FaxId = {_safe_sql_text(fax_id)} AND [LineNo]={_safe_sql_text(line_no)} "
            f"AND ( StatusID <= {status_id} OR {status_id} IN ( 0,11 ))"
        )
        _execute(update_sql, "TelcanAccounts")

        if queue_id != "0":
            _execute(
                f"UPDATE FaxQueue SET FaxQueueID = {_safe_sql_text(queue_id)} WHERE FaxID = {_safe_sql_text(fax_id)}",
                "TelcanAccounts",
            )

        return _json_response({"ResultId": 1, "ResultStr": "Status updated successfully"})
    except Exception as exc:
        return _db_error(endpoint, exc)


def _normalize_voicemail_file_path(wav_file_name: str, voice_mail_type: str) -> tuple[str, str]:
    path = wav_file_name
    vm_type = voice_mail_type
    if path.upper().endswith("PDF"):
        if path.startswith("/var/"):
            path = path.replace("/var/", r"\\10.2.10.2\\").replace("/", "\\")
        elif path.startswith("/mnt/fax/"):
            path = path.replace("/mnt/", r"\\10.2.10.1\\").replace("/", "\\")
        else:
            path = path.replace("/mnt/", r"\\10.2.10.2\\").replace("/", "\\")
        vm_type = "2"
    elif "/memo/" in path:
        vm_type = "1"
        path = path.replace("/var/lib/asterisk/sounds/", r"\\10.2.10.2\media\\").replace("/", "\\")
        if not path.lower().endswith(".wav"):
            path += ".wav"
    else:
        if path.startswith("/mnt/recordings/"):
            path = path.replace("/mnt/", r"\\10.2.10.1\\").replace("/", "\\")
        elif path.startswith("/var/"):
            path = path.replace("/var/lib/asterisk/sounds/", r"\\10.2.10.2\media\\").replace("/", "\\")
        else:
            path = path.replace("spool/asterisk/voicemail/", r"\\10.2.10.2\media\ClientSounds\\").replace("/", "\\")
    return path, vm_type


async def _handle_voice_mail_delete_list(request: Request, endpoint: str, _: BackgroundTasks) -> JSONResponse:
    try:
        voice_mail_id = _param(request, "VoiceMailID").strip()
        if voice_mail_id and voice_mail_id != "0":
            if not _is_int(voice_mail_id):
                return _json_response({"Status": -1})
            affected = _execute(
                " UPDATE TelcanAccounts.dbo.VoiceMail SET FileDeletedOn=GETDATE() "
                f"WHERE VoiceMailID = {_safe_sql_text(voice_mail_id)} AND [FileDeletedOn] IS NULL ",
                "TelcanAccounts",
            )
            if affected > 0:
                status = 1
            elif affected == 0:
                status = 0
            else:
                status = -1
            return _json_response({"Status": status})

        rows = _fetch_all(
            " SELECT TOP 1000 [VoiceMailID], [WAV_FileName] FROM [TelcanAccounts].[dbo].[VoiceMail] "
            "WITH (NOLOCK) WHERE [FileDeletedOn] IS NULL ORDER BY [VoiceMailID] ASC ",
            "TelcanAccounts",
        )
        payload_rows = [
            {"VoiceMailID": row.get("VoiceMailID", ""), "FilePath": row.get("WAV_FileName", "")}
            for row in rows
        ]
        return _json_response({"Rows": payload_rows})
    except Exception as exc:
        return _db_error(endpoint, exc)


async def _handle_voice_mail_2(request: Request, endpoint: str, _: BackgroundTasks) -> JSONResponse:
    try:
        client_no = _param(request, "ClientNo").strip()
        line_no = _param(request, "LineNo").strip()
        dnis = _param(request, "DNIS").strip()
        ani = _param(request, "ANI").strip()
        wav_file_name = _param(request, "File").strip().replace("'", "")
        vpbx_ext_no = _param(request, "EXT").strip() or "0"
        duration = _param(request, "MsgSeconds").strip()
        is_urgent = _param(request, "Urgent").strip()
        queue_id = _param(request, "queueid").strip() or "0"
        original_voice_mail_id = _param(request, "VoiceMailID").strip()
        voice_mail_type = _param(request, "VoiceMailType").strip() or "0"

        if not _is_int(duration):
            duration = "0"
        if not _is_int(vpbx_ext_no):
            vpbx_ext_no = "0"
        if not _is_int(queue_id):
            queue_id = "0"
        if is_urgent != "1":
            is_urgent = "0"

        status = "ERROR"
        voice_mail_id = ""

        if client_no and line_no:
            existing_sql = (
                "Select [LineNo], VoiceMailID From VoiceMail WITH (NOLOCK) "
                f"Where [LineNo] = {_safe_sql_text(line_no)} "
                f"AND VPBXExtNo = '{_safe_sql_text(vpbx_ext_no)}' AND VMailStatus <> 0 "
                "AND SUBSTRING ( WAV_FILENAME, (Len(WAV_FILENAME) + 2 )-  CHARINDEX ( '\\\\', REVERSE ( WAV_FILENAME ) ) , Len(WAV_FILENAME) ) = "
                f"SUBSTRING ( '{_safe_sql_text(wav_file_name)}', (Len('{_safe_sql_text(wav_file_name)}') + 2 ) "
                f"-  CHARINDEX ( '/', REVERSE ( '{_safe_sql_text(wav_file_name)}' ) ) , Len('{_safe_sql_text(wav_file_name)}') )"
            )
            existing = _fetch_one(existing_sql, "TelcanAccounts")
            if existing is None:
                normalized_path, voice_mail_type = _normalize_voicemail_file_path(wav_file_name, voice_mail_type)

                vm_time_row = _fetch_one(
                    " Select DateAdd( hour, T.CurrentOffset, GETUTCDATE()) AS VoiceMailTime FROM Clients C WITH (NOLOCK) "
                    " INNER JOIN TimeZones T WITH (NOLOCK) ON C.TimeZoneId = T.TimeZoneID "
                    f"Where ClientNo = '{_safe_sql_text(client_no)}' ",
                    "TelcanAccounts",
                )
                voice_mail_time = _first_row_value(vm_time_row, None)
                if voice_mail_time is None:
                    voice_mail_time_expr = "GETDATE()"
                else:
                    voice_mail_time_expr = f"'{_safe_sql_text(voice_mail_time)}'"

                mailbox_row = _fetch_one(
                    " Select VB.VoiceMailBoxID from VoiceMailBoxes VB WITH (NOLOCK) "
                    " INNER JOIN VoiceMailBoxAccess VA WITH (NOLOCK) ON VB.VoiceMailBoxID = VA.VoiceMailBoxID "
                    " INNER JOIN Lines L WITH (NOLOCK) ON VA.[LineNo] = L.[LineNo] AND VB.ClientID = L.ClientID "
                    f" WHERE VA.[LineNo] = {_safe_sql_text(line_no)} "
                    f"AND VA.ExtNo= ISNULL(NULLIF('{_safe_sql_text(vpbx_ext_no)}','-1'),'') ",
                    "TelcanAccounts",
                )
                mailbox_id = _to_int((mailbox_row or {}).get("VoiceMailBoxID"), 0)

                original_vm_expr = _safe_sql_text(original_voice_mail_id) if _is_int(original_voice_mail_id) else "NULL"
                insert_sql = (
                    "INSERT INTO VOICEMAIL (ClientNo, [LineNo], [DNIS], [ANI], WAV_FILENAME, VOX_FILENAME, VPBXExtNo, "
                    "MsgSeconds, [UrgentMessage], [DateTime], [MailBoxID], [VoiceMailType], VMailQueueID, OriginalVoiceMailID) VALUES ("
                    f"'{_safe_sql_text(client_no)}','{_safe_sql_text(line_no)}','{_safe_sql_text(dnis)}','{_safe_sql_text(ani)}',"
                    f"'{_safe_sql_text(normalized_path)}','','{_safe_sql_text(vpbx_ext_no)}', {_safe_sql_text(duration)}, "
                    f"{_safe_sql_text(is_urgent)}, {voice_mail_time_expr}, {mailbox_id}, {_safe_sql_text(voice_mail_type)}, "
                    f"{_safe_sql_text(queue_id)}, {original_vm_expr})"
                )
                _execute(insert_sql, "TelcanAccounts")
                status = "OK"

                id_row = _fetch_one(
                    f"SELECT TOP 1 VoiceMailID FROM VoiceMail WITH (NOLOCK) WHERE WAV_FILENAME = '{_safe_sql_text(normalized_path)}' ORDER BY VoiceMailID DESC",
                    "TelcanAccounts",
                )
                voice_mail_id = str((id_row or {}).get("VoiceMailID") or "").strip()

                if _is_int(duration) and int(duration) > 2 and _is_int(voice_mail_id):
                    vm_check_rows = _fetch_all(
                        f"EXEC usp_VoiceMailCheck @LineNo = {_safe_sql_text(line_no)}, @ExtNo='{_safe_sql_text(vpbx_ext_no)}', @VoiceMailID={_safe_sql_text(voice_mail_id)}",
                        "TelcanAccounts",
                    )
                    for vm_row in vm_check_rows:
                        indicator_sql = (
                            " INSERT INTO TelcanSwitch.[dbo].[VMIndicatorQueue]([LineNo],[ExtNo],[ServerIP],TriggeredBy, "
                            "[LightOn], NotifyAttempt, ResultFromPhone, VMailID) VALUES ( "
                            f"{_safe_sql_text(vm_row.get('LineNo', 0))},'{_safe_sql_text(vm_row.get('ExtNo', ''))}',"
                            f"'{_safe_sql_text(vm_row.get('SwitchIP', ''))}', 'SwitchAPI::Voicemail2.asp', 1,10,1,{_safe_sql_text(voice_mail_id)})"
                        )
                        _execute(indicator_sql, "TelcanSwitch")

                        host_private_ip = str(vm_row.get("HostPrivateIP") or "").strip()
                        if host_private_ip:
                            sip_user_id = str(vm_row.get("LineNo") or "").strip()
                            sip_ext = str(vm_row.get("ExtNo") or "").strip()
                            if sip_ext and sip_ext != "-1":
                                sip_user_id = f"{sip_user_id}_{sip_ext}"
                            mwi_url = (
                                "http://10.2.10.249:8080/setvmistatusv2.jsp"
                                f"?ip={host_private_ip}&pin={sip_user_id}&light=1"
                            )
                            try:
                                httpx.get(mwi_url, timeout=2.0)
                            except Exception:
                                pass

                if vpbx_ext_no == "-1":
                    vm_trans_sql = (
                        " SELECT ISNULL([VMTranscription],0) AS VMTranscription FROM LineFeatures WITH (NOLOCK) "
                        "WHERE F_VMTranscription > 0 AND [VMTranscription] = 1 "
                        f"AND [LineNo] = {_safe_sql_text(line_no)}"
                    )
                else:
                    vm_trans_sql = (
                        " SELECT ISNULL(E.[VMTranscription],0) AS VMTranscription FROM LineFeatures LF "
                        "INNER JOIN VPBXExts E ON E.[LineNo] = LF.[LineNo] "
                        "WHERE LF.F_VMTranscription > 0 "
                        f"AND LF.[LineNo] = {_safe_sql_text(line_no)} AND E.ExtNo = '{_safe_sql_text(vpbx_ext_no)}'"
                    )
                vm_trans_row = _fetch_one(vm_trans_sql, "TelcanAccounts")
                if vm_trans_row and _boolish(vm_trans_row.get("VMTranscription")) and _is_int(voice_mail_id):
                    _execute(
                        " INSERT INTO VoiceMailTranscription ([VoiceMailID],[StatusID],[TranscriptionType]) "
                        f"VALUES ({_safe_sql_text(voice_mail_id)}, 0, {_safe_sql_text(voice_mail_type)})",
                        "TelcanAccounts",
                    )
            else:
                voice_mail_id = str(existing.get("VoiceMailID") or "").strip()

        return _json_response({"Status": status, "VoiceMailID": voice_mail_id})
    except Exception as exc:
        return _db_error(endpoint, exc)


def _fix_phone_number(number_to_be_fixed: str, with_ref_to_phone_number: str = "") -> str:
    fixed = str(number_to_be_fixed or "").strip()
    ref_no = str(with_ref_to_phone_number or "").strip()
    if ref_no.startswith("011"):
        ref_no = ref_no[3:]
    if (fixed.startswith("1") and len(fixed) == 11) or fixed.startswith("011"):
        return fixed

    while fixed.startswith("0"):
        fixed = fixed[1:]

    if ref_no and len(fixed) < len(ref_no):
        fixed = ref_no[: len(ref_no) - len(fixed)] + fixed
    return fixed


def _map_callsetup_callerid(template: str, ani: str, dnis: str, line_no: str, allow_blank_to_anonymous: bool) -> str:
    temp_ani = ani if _is_int(ani) else ""
    if temp_ani.startswith("011") and len(temp_ani) > 3:
        temp_ani = temp_ani[3:]
    out = str(template or "")
    up = out.strip().upper()
    if up in {"[BLOCKED]", "[BLOCK]", "0", ""}:
        out = ""
    elif up in {"[ENABLE]", "[ENABLED]", "1"}:
        out = temp_ani
    else:
        out = out.replace("[ANI]", temp_ani).replace("[DNIS]", dnis)

    if allow_blank_to_anonymous and not out and not _is_int(temp_ani):
        out = "Anonymous"
    return out


async def _handle_create_fax_id(request: Request, endpoint: str, _: BackgroundTasks) -> JSONResponse:
    try:
        client_id = _param(request, "ClientId").strip()
        line_no = _param(request, "LineNo").strip()
        fax_no = _param(request, "FaxNo").strip()
        if not (_is_int(client_id) and _is_int(line_no)):
            return _json_response({"ResultID": -1, "Error": "ClientId/LineNo must be numeric"})

        insert_sql = (
            "INSERT INTO FaxQueue (ClientId, [LineNo], FaxNo, FaxFile) "
            f"VALUES ({_safe_sql_text(client_id)}, {_safe_sql_text(line_no)}, '{_safe_sql_text(fax_no)}', '' )"
        )
        _execute(insert_sql, "TelcanAccounts")
        fax_id_row = _fetch_one("SELECT @@IDENTITY As FaxID", "TelcanAccounts")
        fax_id = _first_row_value(fax_id_row, 0)
        return _json_response({"FaxID": fax_id})
    except Exception as exc:
        return _db_error(endpoint, exc)


async def _handle_fax_lookup(request: Request, endpoint: str, _: BackgroundTasks) -> JSONResponse:
    try:
        line_no = _param(request, "LineNo").strip()
        fax_id = _param(request, "FaxId").strip()
        if fax_id.startswith("011"):
            fax_id = fax_id[3:]

        if not line_no or not fax_id:
            return _json_response({"ResultId": 0, "ResultStr": "FaxId and LineNo are required values"})
        if not (_is_int(line_no) and _is_int(fax_id)):
            return _json_response({"ResultId": 0, "ResultStr": "Invalid information received"})

        sql = (
            "SELECT TOP 1 *, REPLACE(REVERSE(LEFT(REVERSE(FaxFile),CHARINDEX('\\\\',REVERSE(FaxFile)))),'\\\\','') AS FaxFileName "
            f"FROM FaxQueue WITH (NOLOCK) WHERE FaxId = {_safe_sql_text(fax_id)} AND [LineNo] = {_safe_sql_text(line_no)}"
        )
        row = _fetch_one(sql, "TelcanAccounts")
        if not row:
            return _json_response({"ResultId": 0, "ResultStr": "Invalid information received"})

        payload: dict[str, Any] = {
            "FaxId": row.get("FaxId", fax_id),
            "FaxNo": row.get("FaxNo", ""),
            "ANI": row.get("LineNo", ""),
            "Status": row.get("Status", ""),
        }
        fax_file_path = str(row.get("FaxFile") or "")
        separate_cover = _boolish(row.get("SaperateCover"))
        if separate_cover:
            payload["FaxFile"] = f"{fax_id}a.tif"
        else:
            if "\\" in fax_file_path:
                payload["FaxFile"] = row.get("FaxFileName", "")
                payload["FaxPath"] = fax_file_path.replace("\\\\10.2.10.1", "\\mnt").replace("\\\\10.2.10.8", "\\mnt").replace("\\", "/")
            else:
                payload["FaxFile"] = f"{fax_id}.tif"

        _execute(
            "UPDATE FaxQueue SET Status ='In Transit', StatusID=2, UpdateTime = GetDate() "
            f"WHERE FaxId = {_safe_sql_text(fax_id)}",
            "TelcanAccounts",
        )
        return _json_response(payload)
    except Exception as exc:
        return _db_error(endpoint, exc)


def _fax_status_text_to_id(status_text: str) -> int:
    s = str(status_text or "").strip().upper()
    mapping = {
        "INITIALIZING": 0,
        "NEW": 1,
        "IN TRANSIT": 2,
        "DIALING": 3,
        "CONNECTED": 4,
        "CONNECTED_FAX": 4,
        "SENDINGPAGE": 5,
        "UNKNOWNERROR": 10,
        "FAILED": 11,
        "SUCCESS": 12,
    }
    return mapping.get(s, 10)


async def _handle_fax_status_check(request: Request, endpoint: str, _: BackgroundTasks) -> JSONResponse:
    try:
        fax_id = _param(request, "FaxId").strip()
        line_no = _param(request, "LineNo").strip()
        if line_no.startswith("1") and len(line_no) == 11:
            line_no = line_no[1:]

        if line_no == "":
            return _json_response({"ResultId": 0, "ResultStr": "FaxId and LineNo are required values and are missing"})
        if fax_id == "":
            return _json_response({"ResultId": 0, "ResultStr": "FaxID is a required field and is missing"})
        if not (_is_int(line_no) and _is_int(fax_id)):
            return _json_response({"ResultId": 0, "ResultStr": "Invalid information provided"})

        sql = (
            "SELECT [Status], [StatusID] FROM [TelcanAccounts].[dbo].[FaxQueue] WITH (NOLOCK) "
            f"WHERE FaxId = {_safe_sql_text(fax_id)} AND [LineNo] = {_safe_sql_text(line_no)}"
        )
        row = _fetch_one(sql, "TelcanAccounts")
        if not row:
            return _json_response({"ResultId": 0, "ResultStr": "Invalid information provided"})

        status_name = str(row.get("Status") or "")
        status_id = row.get("StatusID")
        if status_id is None or not _is_int(status_id):
            status_id = _fax_status_text_to_id(status_name)
        return _json_response({"ResultId": status_id, "ResultStr": status_name})
    except Exception as exc:
        return _db_error(endpoint, exc)


async def _handle_fax_status(request: Request, endpoint: str, _: BackgroundTasks) -> JSONResponse:
    try:
        fax_id = _param(request, "FaxId").strip()
        line_no = _param(request, "LineNo").strip()
        status = _param(request, "Status").strip() or "FAILED"
        comments = _decode_param(_param(request, "Comments").strip())
        if status.strip().upper() == "SUCCESS":
            for part in comments.split("|"):
                compact = part.replace(" ", "")
                if compact[:8].upper() == "FAXPAGES":
                    parts = compact.split("=", 1)
                    if len(parts) == 2 and parts[1]:
                        status = f"{parts[1]} Page(s) Sent"
                    break

        if line_no == "":
            return _json_response({"ResultId": 0, "ResultStr": "FaxId and LineNo are required values and are missing"})
        if status == "":
            return _json_response({"ResultId": 0, "ResultStr": "Status is a required field and is missing"})
        if not (_is_int(line_no) and _is_int(fax_id)):
            return _json_response({"ResultId": 0, "ResultStr": "Invalid information provided"})

        row = _fetch_one(
            f"SELECT TOP 1 FaxId FROM FaxQueue WITH (NOLOCK) WHERE FaxId = {_safe_sql_text(fax_id)} AND [LineNo] = {_safe_sql_text(line_no)}",
            "TelcanAccounts",
        )
        if not row:
            return _json_response({"ResultId": 0, "ResultStr": "Invalid information provided"})
        if len(status) > 20:
            return _json_response({"ResultId": 0, "ResultStr": "Invalid status value"})

        _execute(
            "UPDATE FaxQueue SET "
            f"[Status]='{_safe_sql_text(status)}', [Comments]='{_safe_sql_text(comments)}', UpdateTime = GetDate() "
            f"WHERE FaxId = {_safe_sql_text(fax_id)} AND [LineNo]={_safe_sql_text(line_no)} AND [Status] <> 'SUCCESS'",
            "TelcanAccounts",
        )
        return _json_response({"ResultId": 1, "ResultStr": "Status updated successfully"})
    except Exception as exc:
        return _db_error(endpoint, exc)


async def _handle_fax_status_update(request: Request, endpoint: str, _: BackgroundTasks) -> JSONResponse:
    try:
        proc = _param(request, "proc").strip().lower()
        fax_id = _param(request, "FaxID").strip()
        server_ip = _param(request, "ServerIP").strip()
        if not _is_int(fax_id):
            return _json_response({"Result": 0, "Error": "FaxID must be numeric"})

        base = f"UPDATE FaxQueue SET FaxServerIP = '{_safe_sql_text(server_ip)}', "
        if proc == "status":
            cnn_status = _param(request, "CnnStatus").strip()
            fax_status = _param(request, "FaxStatus").strip()
            result_status = _param(request, "ResultStatus").strip()
            used_lcr = _param(request, "UsedLCR").strip()
            lcr_counter = _param(request, "Counter").strip()
            if not _is_int(result_status):
                result_status = "0"
            if not _is_int(lcr_counter):
                lcr_counter = "1"
            if not _is_int(cnn_status):
                cnn_status = "0"
            if not _is_int(fax_status):
                fax_status = "0"
            if not _is_int(used_lcr):
                used_lcr = "0"

            insert_rec_sql = (
                "INSERT INTO TelcanRecording..FaxRecords ([FaxID],[FaxServerIP],[StatusUpdateTime],[CnnStatus],[FaxStatus],[ResultStatus],[UsedLCR],[LCRCounter]) "
                f"Values({_safe_sql_text(fax_id)}, '{_safe_sql_text(server_ip)}', GETDATE(), {_safe_sql_text(cnn_status)}, "
                f"{_safe_sql_text(fax_status)}, {_safe_sql_text(result_status)}, {_safe_sql_text(used_lcr)}, {_safe_sql_text(lcr_counter)})"
            )
            _execute(insert_rec_sql, "TelcanAccounts")

            update_sql = (
                base
                + f"CnnStatus = {_safe_sql_text(cnn_status)}, FaxStatus = {_safe_sql_text(fax_status)}, "
                + f"ResultStatus = {_safe_sql_text(result_status)}, UsedLCR = {_safe_sql_text(used_lcr)}, "
                + "StatusUpdatetime = GETDATE() "
                + f"WHERE FaxID = {_safe_sql_text(fax_id)}"
            )
            _execute(update_sql, "TelcanAccounts")
        else:
            ref_id = _param(request, "RefID").strip()
            update_sql = base + f"FaxRefID = '{_safe_sql_text(ref_id)}' WHERE FaxID = {_safe_sql_text(fax_id)}"
            _execute(update_sql, "TelcanAccounts")

        return _json_response({"Result": 1})
    except Exception as exc:
        return _db_error(endpoint, exc)


async def _handle_call_setup_v308(request: Request, endpoint: str, _: BackgroundTasks) -> JSONResponse:
    try:
        reseller_no = _param(request, "ResellerNo").strip()
        line_no = _param(request, "LineNo").strip().replace("*", "").replace("#", "")
        pin = _param(request, "PIN").strip()
        ani = _param(request, "ANI").strip()
        dnis = _param(request, "DNIS").strip()
        selected_lang = _param(request, "LangID").strip()

        if line_no.startswith("1") and len(line_no) == 11:
            line_no = line_no[1:]

        if line_no and line_no != "0":
            sql = (
                "EXEC spGetLineInfo3 "
                f"'{_safe_sql_text(reseller_no)}', '{_safe_sql_text(line_no)}','', "
                f"'{_safe_sql_text(ani)}','{_safe_sql_text(dnis)}'"
            )
        else:
            sql = (
                "EXEC spGetCCLineInfo2 "
                f"'{_safe_sql_text(reseller_no)}',0,'{_safe_sql_text(pin)}', "
                f"'{_safe_sql_text(ani)}','{_safe_sql_text(dnis)}'"
            )

        row = _fetch_one(sql, "TelcanAccounts")
        if not row:
            return _json_response({"ResultID": 0, "L_DestinationNo": "", "R_CustomerServicePhone": "", "L_OutConnectTimeout": "60"})

        payload: dict[str, Any] = {}
        result_id = _to_int(row.get("ResultID"), 0)
        customer_service_phone = str(row.get("R_CustomerServicePhone") or "")
        effective_line_no = str(row.get("L_LineNo") or line_no or "")
        line_type_id = _to_int(row.get("L_LineTypeID"), 0)
        destination_no = ""
        if result_id == 1 and line_type_id == 4 and len(str(row.get("L_CallbackNo") or "").strip()) > 7:
            destination_no = str(row.get("L_CallbackNo") or "").strip()

        for field_name, field_value in row.items():
            upper = str(field_name).upper()
            if upper in {"R_CUSTOMERSERVICEPHONE", "RESULTID"}:
                continue
            if upper == "L_CALLERID":
                payload[field_name] = _map_callsetup_callerid(str(field_value or ""), ani, dnis, effective_line_no, True)
            elif upper == "L_OUTCALLERID":
                src = str(field_value or "").strip() or effective_line_no
                payload[field_name] = _map_callsetup_callerid(src, ani, dnis, effective_line_no, False).replace(" ", "")
            elif upper == "L_LANGID":
                lang_id = _to_int(field_value, 1)
                if (not selected_lang) or (not _is_int(selected_lang)):
                    if lang_id == 0:
                        lang_id = 1
                else:
                    selected_val = _to_int(selected_lang, 1)
                    if selected_val > 0 and lang_id in {0, -1}:
                        lang_id = selected_val
                payload["L_LangID"] = lang_id
            else:
                payload[field_name] = field_value

        if result_id == 1:
            dnis_for_lookup = (dnis or effective_line_no).strip()
            if dnis_for_lookup and dnis_for_lookup != effective_line_no and _is_int(dnis_for_lookup) and len(dnis_for_lookup) <= 18:
                speed_row = _fetch_one(
                    f"Select SpeedDialNo From InboundLines WITH (NOLOCK) WHERE [LineNo]='{_safe_sql_text(dnis_for_lookup)}'",
                    "TelcanAccounts",
                )
                speed_dial = str((speed_row or {}).get("SpeedDialNo") or "").strip()
                if speed_dial:
                    dest_row = _fetch_one(
                        "Select Top 1 TelNo from SpeedDial WITH (NOLOCK) "
                        f"WHERE [LineNo]='{_safe_sql_text(effective_line_no)}' AND Memory='{_safe_sql_text(speed_dial)}'",
                        "TelcanAccounts",
                    )
                    if dest_row:
                        destination_no = str(dest_row.get("TelNo") or destination_no)

        payload["ResultID"] = result_id
        payload["L_DestinationNo"] = destination_no
        payload["R_CustomerServicePhone"] = _fix_phone_number(customer_service_phone)
        payload["L_OutConnectTimeout"] = "60"
        return _json_response(payload)
    except Exception as exc:
        return _db_error(endpoint, exc)


async def _handle_call_end(_: Request, __: str, ___: BackgroundTasks) -> JSONResponse:
    return _json_response({"URLStatus": "OK"})


async def _handle_blind_transfer_info(request: Request, endpoint: str, _: BackgroundTasks) -> JSONResponse:
    try:
        proc = _param(request, "proc").strip().lower()
        sip_id = _param(request, "sip_id").strip()
        dest_number = _param(request, "dest_number").strip()
        dnis = _param(request, "dnis").strip()
        result_id = "0"
        payload: dict[str, Any] = {}

        if proc == "add":
            connection_time = _param(request, "connection_time").strip()
            dest_number_prefix = _param(request, "dest_number_prefix").strip()
            ani = _param(request, "ani").strip()
            if sip_id and ani:
                server_ip = (request.client.host if request.client else "") or ""
                query = (
                    "INSERT INTO TelcanMonitor..BlindTransferInfo "
                    "([sip_id],[date_time],[connection_time],[dest_number],[dest_number_prefix],[dnis],[ani],[server_ip]) "
                    f"Values('{_safe_sql_text(sip_id)}', GETDATE(), '{_safe_sql_text(connection_time)}', "
                    f"'{_safe_sql_text(dest_number)}', '{_safe_sql_text(dest_number_prefix)}', "
                    f"'{_safe_sql_text(dnis)}', '{_safe_sql_text(ani)}', '{_safe_sql_text(server_ip)}')"
                )
                _execute(query, "TelcanAccounts")
                result_id = "1"
        elif proc == "delete":
            query = f"UPDATE TelcanMonitor..BlindTransferInfo SET CallEnded = 1 WHERE sip_id = '{_safe_sql_text(sip_id)}'"
            _execute(query, "TelcanAccounts")
            result_id = "1"
        elif proc in {"get", "read"}:
            query = "SELECT TOP 1 * FROM TelcanMonitor..BlindTransferInfo WHERE "
            if proc == "get":
                query += f"sip_id = '{_safe_sql_text(sip_id)}'"
            else:
                query += (
                    f"dest_number = '{_safe_sql_text(dest_number)}' AND dnis = '{_safe_sql_text(dnis)}' "
                    "AND date_time > DATEADD(MINUTE, -60, GETDATE()) ORDER BY rec_id DESC"
                )
            row = _fetch_one(query, "TelcanAccounts")
            if row:
                payload.update(
                    {
                        "sip_id": row.get("sip_id", ""),
                        "connection_time": row.get("connection_time", ""),
                        "dest_number": row.get("dest_number", ""),
                        "dest_number_prefix": row.get("dest_number_prefix", ""),
                        "dnis": row.get("dnis", ""),
                        "ani": row.get("ani", ""),
                    }
                )
                result_id = "1"

        payload["result_id"] = result_id
        return _json_response(payload)
    except Exception as exc:
        return _db_error(endpoint, exc)


async def _handle_leg2_connected(request: Request, endpoint: str, _: BackgroundTasks) -> JSONResponse:
    try:
        queue_id = _param(request, "queueid").strip()
        leg2_tel_no = _param(request, "leg2tellno").strip()
        answered_by_line = ""
        answered_by_ext = ""
        if "_" in leg2_tel_no:
            parts = leg2_tel_no.split("_", 1)
            answered_by_line = parts[0]
            answered_by_ext = parts[1]
        else:
            answered_by_line = leg2_tel_no

        if _is_int(queue_id):
            _execute(
                "UPDATE QueueMonitor SET QueueExitTime = GETDATE(), "
                f"AnsweredByLineNo = '{_safe_sql_text(answered_by_line)}', "
                f"AnsweredByExtension ='{_safe_sql_text(answered_by_ext)}' "
                f"WHERE queueid = {_safe_sql_text(queue_id)}",
                "TelcanMonitor",
            )
            _execute(
                f"UPDATE Monitor SET Leg2TelNo = '{_safe_sql_text(leg2_tel_no)}', StatusID = 3 "
                f"WHERE QueueID = {_safe_sql_text(queue_id)}",
                "TelcanMonitor",
            )
        return _json_response({"ResultID": 1})
    except Exception as exc:
        return _db_error(endpoint, exc)


async def _handle_update_call_status(request: Request, endpoint: str, _: BackgroundTasks) -> JSONResponse:
    try:
        line_no = _param(request, "LineNo").strip()
        recs = 0
        if _is_int(line_no):
            recs = _execute(
                f"UPDATE Lines SET FirstUseDateTime=getDate() WHERE [LineNo]={_safe_sql_text(line_no)}",
                "TelcanAccounts",
            )
        return _json_response({"RecordsUpdated": recs, "Status": "OK"})
    except Exception as exc:
        return _db_error(endpoint, exc)


async def _handle_vm_indicator_get(request: Request, endpoint: str, _: BackgroundTasks) -> JSONResponse:
    try:
        server_ip = _param(request, "ServerIP").strip()
        api_version = _param(request, "v").strip()
        rec_id = _param(request, "RecID").strip()
        result_from_device = _param(request, "ResultFromDevice").strip()
        result_info = _param(request, "ResultInfo").strip()

        if rec_id and result_from_device:
            if not _is_int(rec_id):
                return _json_response({"Result": 0, "Error": "RecID must be numeric"})
            update_sql = (
                "UPDATE VMIndicatorQueue SET "
                f"ResultFromPhone = '{_safe_sql_text(result_from_device)}', "
                f"ResultInfo = '{_safe_sql_text(result_info)}', LastUpdateTime = GETDATE() "
                f"WHERE RecID = {_safe_sql_text(rec_id)}"
            )
            _execute(update_sql, "TelcanSwitch")
            return _json_response({"Result": 1})

        query = (
            "SELECT *, ISNULL((SELECT CAST (lightOn AS VARCHAR) + '_' + CAST(NotifyAttempt AS VARCHAR) + '_' "
            " + CAST(ISNULL(PhoneIDReference, 0) AS VARCHAR) FROM VMIndicatorQueue WITH (NOLOCK) "
            "WHERE RecID = x.RecID AND ISNULL(ResultFromPhone, 0) <> 1 AND ISNULL(ResultInfo, '') = ''), '') AS lightOn_NotifyAttempt "
            "FROM ( SELECT [LineNo], ExtNo, MAX(RecID) AS RecID FROM VMIndicatorQueue WITH (NOLOCK) "
            f"WHERE InsertTime > DATEADD(MINUTE, -30, GETDATE()) AND ServerIP = '{_safe_sql_text(server_ip)}' "
            "GROUP BY [LineNo], ExtNo ) AS X"
        )
        rows = _fetch_all(query, "TelcanSwitch")
        out_rows: list[dict[str, Any]] = []
        ids_to_update: list[str] = []
        for row in rows:
            light_pack = str(row.get("lightOn_NotifyAttempt") or "").strip()
            if not light_pack:
                continue
            parts = light_pack.split("_")
            if len(parts) < 2:
                continue
            light_on = parts[0]
            notify_attempt = _to_int(parts[1], 0)
            phone_ref = parts[2] if len(parts) > 2 else "0"
            if notify_attempt >= 10:
                continue

            line_no = str(row.get("LineNo") or "")
            ext_no = str(row.get("ExtNo") or "").strip()
            peer = f"{line_no}_{ext_no}" if ext_no else line_no
            item: dict[str, Any] = {"Peer": peer, "LightOn": light_on}
            if api_version in {"1", "2"}:
                item["RecID"] = row.get("RecID", "")
            if api_version == "2":
                item["PhoneIDReference"] = phone_ref
            out_rows.append(item)
            ids_to_update.append(str(row.get("RecID") or "0"))

        if ids_to_update:
            id_list = ",".join(_safe_sql_text(x) for x in ids_to_update if _is_int(x))
            if id_list:
                _execute(
                    f"UPDATE VMIndicatorQueue SET NotifyAttempt = NotifyAttempt + 1 WHERE RecID IN({id_list})",
                    "TelcanSwitch",
                )
        return _json_response({"Rows": out_rows})
    except Exception as exc:
        return _db_error(endpoint, exc)


async def _handle_transcription_save(request: Request, endpoint: str, _: BackgroundTasks) -> JSONResponse:
    try:
        queue_id = _param(request, "QueueID").strip()
        file_path = _param(request, "FileNameFullPath").strip()
        file_size = _param(request, "FileSize").strip()
        suspected = _param(request, "Suspected").strip()
        server_id = _param(request, "ServerID").strip()
        reason = _param(request, "ReasonForDetection").strip()[:1000]

        rec_id: Any = 0
        if queue_id and queue_id != "0" and _is_int(queue_id):
            if not _is_int(file_size):
                file_size = "0"
            if not _is_int(suspected):
                suspected = "0"
            insert_sql = (
                "INSERT INTO TelcanRecording.dbo.MemoTranscription "
                "(QueueID, FileNameFullPath, FileSize, Suspected, ServerID, ReasonForDetection) VALUES ("
                f"{_safe_sql_text(queue_id)}, '{_safe_sql_text(file_path)}', {_safe_sql_text(file_size)}, "
                f"{_safe_sql_text(suspected)}, '{_safe_sql_text(server_id)}', '{_safe_sql_text(reason)}' )"
            )
            _execute(insert_sql, "TelcanAccounts")
            rec_row = _fetch_one("SELECT @@IDENTITY As RecID", "TelcanAccounts")
            rec_id = _first_row_value(rec_row, 0)

        return _json_response({"RecID": rec_id})
    except Exception as exc:
        return _db_error(endpoint, exc)


async def _handle_switch_config_get_old(request: Request, endpoint: str, _: BackgroundTasks) -> JSONResponse:
    try:
        server_ip = _param(request, "ServerIP").strip()
        query = (
            "SELECT ConfigKey, ConfigValue FROM SwitchConfig s WITH (NOLOCK) WHERE ConfigKey <> 'PROXYIP' "
            "UNION ALL "
            "SELECT ConfigKey, ConfigValue FROM ( "
            "SELECT TOP 1 ConfigKey, ConfigValue FROM SwitchConfig s WITH (NOLOCK) "
            f"WHERE ConfigKey = 'PROXYIP' AND ('{_safe_sql_text(server_ip)}' LIKE ISNULL(ServerIP, '') OR ServerIP IS NULL) "
            "ORDER BY Priority DESC) AS X"
        )
        rows = _fetch_all(query, "TelcanSwitch")
        payload: dict[str, Any] = {}
        for row in rows:
            k = str(row.get("ConfigKey") or "").strip()
            if not k:
                continue
            payload[k] = row.get("ConfigValue", "")
        payload["ResultID"] = 1 if payload else -1
        return _json_response(payload)
    except Exception as exc:
        return _db_error(endpoint, exc)


async def _handle_get_caller_id(request: Request, endpoint: str, _: BackgroundTasks) -> JSONResponse:
    try:
        version = _param(request, "V").strip()
        ani_raw = _decode_param(_param(request, "ANI")).strip()
        if ";" in ani_raw:
            ani_raw = ani_raw.split(";", 1)[0]
        dnis = _decode_param(_param(request, "DNIS")).strip()
        line_no = _decode_param(_param(request, "LineNo")).strip()
        is_provider = _decode_param(_param(request, "IsProvider")).strip()
        caller_name = _decode_param(_param(request, "CallerName")).strip().replace("'", "")
        lcr = _param(request, "LCR").strip()

        valid = "0123456789_"
        ani = ani_raw if ani_raw.casefold() == "anonymous" else _keep_only_chars(ani_raw, valid)
        dnis = _keep_only_chars(dnis, valid)
        line_no = _keep_only_chars(line_no, valid)
        is_provider = _keep_only_chars(is_provider, valid)
        if is_provider not in {"1", "3"}:
            is_provider = "0"

        if len(ani) > 10 and not ani.startswith(("1", "0", "+")) and "_" not in ani:
            ani = f"+{ani}"

        if version == "3":
            sql = (
                " EXEC [dbo].[usp_GetCallerIDV3] "
                f"@ANI='{_safe_sql_text(ani)}', @DNIS='{_safe_sql_text(dnis)}', "
                f"@LineNo='{_safe_sql_text(line_no)}', @IsProvider={_safe_sql_text(is_provider)}, "
                f"@CallerName='{_safe_sql_text(caller_name)}' "
            )
        else:
            sql = f" EXEC [dbo].[usp_GetCallerID] @ANI='{_safe_sql_text(ani)}', @DNIS='{_safe_sql_text(dnis)}' "

        caller = ""
        if ani:
            row = _fetch_one(sql, "TelcanAccounts")
            caller = str((row or {}).get("CallerID") or ani).replace('"', "")
        if not caller:
            original_ani = _param(request, "ANI").strip()
            if original_ani.casefold() == "anonymous" or caller_name.casefold() == "anonymous":
                caller = "anonymous<anonymous>"
            elif original_ani.casefold() == "restricted":
                caller = f"anonymous<{line_no}>"
            else:
                caller = ani or "Anonymous"

        if caller in {"<UNKNOWN>", "<Anonymous>", "Anonymous"} and lcr == "11":
            caller = (("1" if len(line_no) == 10 else "") + line_no)

        return _json_response({"CallerID": caller})
    except Exception as exc:
        return _db_error(endpoint, exc)


async def _handle_provider_lookup_v3(request: Request, endpoint: str, _: BackgroundTasks) -> JSONResponse:
    try:
        provider_id = _param(request, "ProviderID").strip()
        tel_no = _param(request, "TelNo").replace("*", "").replace("#", "").strip()
        ani = _param(request, "ANI").strip()
        if not _is_int(provider_id):
            return _json_response({"ResultID": -1, "Error": "ProviderID must be numeric"})

        caller_server_ip = (request.client.host if request.client else "") or ""
        provider_ip = ""
        provider_prefix = ""
        ip_sql = (
            "SELECT TOP 1 IPAddress, ISNULL(PrefixValue, '') AS PrefixValue "
            "FROM ProviderIPs WHERE Inbound = 0 "
            f"AND ProviderID = {_safe_sql_text(provider_id)} "
            f"AND '{_safe_sql_text(caller_server_ip)}' LIKE Subnet"
        )
        ip_row = _fetch_one(ip_sql, "TelcanLCR")
        if ip_row:
            provider_ip = str(ip_row.get("IPAddress") or "").strip()
            provider_prefix = str(ip_row.get("PrefixValue") or "").strip()

        sql = (
            "EXEC usp_GetProviderInfo "
            f"@ProviderID={_safe_sql_text(provider_id)}, @ANI='{_safe_sql_text(ani)}', @RingToNumber='{_safe_sql_text(tel_no)}' "
        )
        row = _fetch_one(sql, "TelcanLCR")
        payload: dict[str, Any] = {}
        if row:
            for k, v in row.items():
                ku = str(k).upper()
                if ku == "BILLINGINTERVAL":
                    bi = _to_int(v, 0)
                    if tel_no and _is_int(tel_no) and tel_no.startswith("01152") and bi < 60:
                        bi = 60
                    payload["BillingInterval"] = bi
                elif ku == "IPADDRESS":
                    payload["IPAddress"] = provider_ip or v
                elif ku == "PROVIDERPREFIX":
                    payload["ProviderPrefix"] = provider_prefix or v
                else:
                    payload[k] = v
        payload["PConnectTimeout"] = 45
        return _json_response(payload)
    except Exception as exc:
        return _db_error(endpoint, exc)


async def _handle_get_provider_info(request: Request, endpoint: str, _: BackgroundTasks) -> JSONResponse:
    """
    Compatibility endpoint for legacy GetproviderInfo.asp.
    Reuse ProviderLookupV3 behavior so existing clients can migrate without changes.
    """
    return await _handle_provider_lookup_v3(request, endpoint, _)


def _is_tollfree_no(line_no: str) -> bool:
    digits = re.sub(r"[^0-9]", "", line_no or "")
    prefix = ""
    if len(digits) == 11 and digits.startswith("1"):
        prefix = digits[:4]
    elif len(digits) == 10:
        prefix = digits[:3]
    return prefix in {"1800", "1866", "1877", "1888", "800", "866", "877", "888"}


def _is_payphone_ani2(ani2: str) -> bool:
    a = str(ani2 or "").replace(">", "")
    return a in {"25", "27", "29", "70"}


async def _handle_get_rates(request: Request, endpoint: str, _: BackgroundTasks) -> JSONResponse:
    try:
        l_rate_cid = _param(request, "LRateCID").strip() or "0"
        r_rate_cid = _param(request, "RRateCID").strip() or "0"
        a_rate_cid = _param(request, "ARateCID").strip() or "0"
        p_rate_cid = _param(request, "PRateCID").strip() or "0"
        tel_no = _param(request, "TelNo").replace(" ", "").strip()
        ani_no = _param(request, "ANINO").strip()
        ani2 = _param(request, "ANI2").strip()
        if "," in ani2:
            ani2 = ani2.split(",", 1)[0]
        cmp_entire = _param(request, "cmpEntire").strip() or "0"
        inbound = _param(request, "Inbound").strip() or "0"
        area_code = _param(request, "AreaCode").strip()
        client_no = _param(request, "ClientNo").strip()
        client_id = _param(request, "ClientID").strip() or "0"
        line_no = _param(request, "LineNo").strip() or "0"
        dial_plan_id = _param(request, "DialPlanID").strip() or "0"
        virtual_did = _param(request, "VirtualDID").strip()
        try_count = _param(request, "TryCount").strip() or "1"
        r_leg1_bi = _param(request, "RLeg1BillingInterval").strip()
        r_leg2_bi = _param(request, "RLeg2BillingInterval").strip()

        voip_enabled = 0
        server_ip = ""
        l_balance: Any = 0
        tel_no_user_agent = ""
        tel_no_line_no = ""
        delay_before_connect = 0
        sip_connect_timeout = 0
        original_tel_no = tel_no
        l_rate_category_id_out = l_rate_cid
        l_billing_interval: Any = 0
        leg1_rate: Any = -1
        rate_id: Any = 0
        result_val: Any = 0
        rate: Any = 0
        lcr: Any = ""

        if tel_no and inbound == "0":
            if area_code and tel_no[:1] != "0" and _is_int(tel_no) and area_code[:1] == "1" and len(tel_no) == 10:
                tel_no = f"1{tel_no}"
            if not _is_int(client_id):
                client_id = "0"
            if not _is_int(dial_plan_id):
                dial_plan_id = "0"
            virtual_did_int = "1" if _boolish(virtual_did) else "0"
            resolve_sip = "1" if try_count == "1" else "0"
            dial_sql = (
                "EXEC spGetDialPlanV2 "
                f"@ClientNo='{_safe_sql_text(client_no)}',@ClientID={_safe_sql_text(client_id)}, "
                f"@LineNo='{_safe_sql_text(line_no)}', @TelNo='{_safe_sql_text(tel_no)}', "
                f"@DialPlanID={_safe_sql_text(dial_plan_id)}, @AreaCode = '{_safe_sql_text(area_code)}', "
                f"@VirtualDID = {virtual_did_int}, @ResolveSip = {resolve_sip}"
            )
            dial_row = _fetch_one(dial_sql, "TelcanAccounts")
            if dial_row:
                tel_no = str(dial_row.get("TelNo") or tel_no)
                voip_enabled = 1 if _boolish(dial_row.get("VoIPEnabled")) else 0
                server_ip = str(dial_row.get("ServerIP") or "")
                l_balance = dial_row.get("L_Balance", 0)
                tel_no_user_agent = str(dial_row.get("TelNoUserAgent") or "")
                tel_no_line_no = str(dial_row.get("TelNoLineNo") or "")
                tel_no_tel_no = str(dial_row.get("TelNoTelNo") or "")
                original_tel_no = tel_no_tel_no or original_tel_no
                if tel_no_user_agent:
                    sip_connect_timeout = 40

            if voip_enabled == 0 and _is_int(tel_no):
                if not tel_no.startswith(("1", "011", "00")) and len(tel_no) > 5:
                    tel_no = f"1{tel_no}"

        rate_sql = f"EXEC spRate3 {l_rate_cid},{r_rate_cid},"
        if not tel_no:
            rate_sql += "'',"
        elif voip_enabled == 1:
            rate_sql += "'555',"
        else:
            rate_sql += f"'{_safe_sql_text(tel_no)}',"
        if not ani_no:
            ani_expr = "''"
        else:
            ani_expr = f"'{_safe_sql_text(ani_no)}'"
        rate_sql += f"{cmp_entire},{p_rate_cid},{inbound},{ani_expr},{a_rate_cid}"
        rate_row = _fetch_one(rate_sql, "TelcanRates")

        payload: dict[str, Any] = {"L_Balance": l_balance}
        if rate_row:
            for k, v in rate_row.items():
                ku = str(k).upper()
                if ku == "L_RATE":
                    rate = v
                if ku == "LCR":
                    lcr = v
                if ku == "RATEID":
                    rate_id = v
                if ku == "RESULT":
                    result_val = v
                payload[k] = v
        else:
            payload["RateID"] = 0

        l_payphone = 0
        r_payphone = 0
        p_payphone = 0
        if _is_tollfree_no(line_no) and _is_payphone_ani2(ani2) and inbound == "1":
            pay_sql = f"EXEC spRate3 {l_rate_cid},{r_rate_cid},'PAYPHONE',0,{p_rate_cid},{inbound},'{_safe_sql_text(ani_no)}',{a_rate_cid}"
            pay_row = _fetch_one(pay_sql, "TelcanRates")
            if pay_row:
                l_payphone = pay_row.get("L_Rate", 0)
                r_payphone = pay_row.get("R_Rate", 0)
                p_payphone = pay_row.get("P_Rate", 0)

        rbilling = r_leg2_bi or r_leg1_bi or ""
        payload.update(
            {
                "L_Rate": rate,
                "LCR": lcr,
                "RBillingInterval": rbilling,
                "RLeg1BillingInterval": r_leg1_bi,
                "RLeg2BillingInterval": r_leg2_bi,
                "TelNo": tel_no,
                "VoIPEnabled": voip_enabled,
                "L_PayphoneCharge": l_payphone,
                "R_PayphoneCharge": r_payphone,
                "P_PayphoneCharge": p_payphone,
                "ServerIP": server_ip,
                "L_ProductId": 0,
                "UserAgent": tel_no_user_agent,
                "TelNoLineNo": tel_no_line_no,
                "DelayBeforeConnect": delay_before_connect,
                "DialPlanId": dial_plan_id,
                "TryCount": try_count,
                "SipConnectTimeout": sip_connect_timeout,
                "OriginalTelNo": original_tel_no,
                "L_RateCategoryId": l_rate_category_id_out,
                "L_BillingInterval": l_billing_interval,
                "LineNo": line_no,
                "Leg1Rate": leg1_rate,
                "RateID": rate_id,
                "Result": result_val,
            }
        )
        return _json_response(payload)
    except Exception as exc:
        return _db_error(endpoint, exc)


def _normalize_dnis_v405(raw_dnis: str) -> tuple[str, str]:
    dnis = str(raw_dnis or "").strip()
    original = dnis
    if len(dnis) >= 11:
        if dnis.startswith("8888988"):
            dnis = dnis[7:]
        if dnis.startswith("1988"):
            dnis = dnis[4:]
        if dnis.startswith("78601*"):
            dnis = dnis[6:]
        original = dnis
        if dnis.startswith("1") and len(dnis) == 11:
            dnis = dnis[1:]
    return dnis, original


def _create_cts_queue_id_v2(dnis: str, ani: str, app_name: str) -> str:
    sql = (
        "EXEC spSetCTSQueueV2 "
        f"@DNIS='{_safe_sql_text(dnis)}',@ANI='{_safe_sql_text(ani)}',"
        f"@Description='Callture Call Manager',@ApplicationName='{_safe_sql_text(app_name)}'"
    )
    row = _fetch_one(sql, "TelcanSQLLogs")
    return str((row or {}).get("CTSQueueID") or "0")


def _trigger_callback_v405(
    s_dnis: str,
    s_ani: str,
    reseller_no: str,
    always_ask_for_pin: bool,
    cts_callback: bool,
) -> tuple[int, str, str]:
    temp_sql = f"EXEC spVerifyCBRequest '{_safe_sql_text(s_ani)}','{_safe_sql_text(s_dnis)}'"
    temp_rs = _fetch_one(temp_sql, "TelcanAccounts") or {}
    temp_result_id = _to_int(temp_rs.get("ResultID"), 0)
    result_str = str(temp_rs.get("Result") or "")
    current_ani = s_ani
    if temp_result_id != 0:
        return 5, "", result_str

    did_pin = s_dnis
    leg1_tel_no = s_ani
    if not always_ask_for_pin:
        temp_sql = (
            "EXEC spGetCCLineInfo2 "
            f"'{_safe_sql_text(reseller_no)}', 0, '', '{_safe_sql_text(s_ani)}'"
        )
        temp_rs = _fetch_one(temp_sql, "TelcanAccounts") or {}
        if _to_int(temp_rs.get("ResultID"), 0) == 1:
            did_pin = str(temp_rs.get("L_LineNo") or did_pin)
            callback_no = str(temp_rs.get("L_CallbackNo") or "")
            if len(callback_no) >= 10 and callback_no[:1] in {"1", "0"} and len(s_ani) >= 2:
                if callback_no[-(len(s_ani) - 2) :] == s_ani[-(len(s_ani) - 2) :]:
                    leg1_tel_no = callback_no

    if cts_callback:
        temp_sql = (
            "EXEC spSetQueue "
            f"{_safe_sql_text(did_pin)}, @Leg1TelNo='{_safe_sql_text(leg1_tel_no)}', @Leg2TelNo='', "
            "@Web800CallID=0, @ApplicationName='Asterisk Queue Manager', "
            "@ProcessDelaySec=3, @PreferredServers='', @LineTypeID=1"
        )
        temp_rs = _fetch_one(temp_sql, "TelcanQueue") or {}
        return _to_int(temp_rs.get("ResultID"), 0), current_ani, str(temp_rs.get("ResultStr") or "")

    current_ani = leg1_tel_no.strip()
    return 0, current_ani, "Callback Triggered"


def _get_authentication_v405(
    ani: str,
    inbound_line_type_id: int,
    reseller_id: str,
) -> tuple[int, dict[str, Any], str]:
    i_auth_type_id = 0
    i_auth_user_type = 0
    auth_user_id = ""
    auth_rno = ""
    auth_rid = ""
    phone_password = ""
    temp_result_id = 0
    result = ""

    checked_ani = ani if _is_int(ani) else "9999999999"
    if inbound_line_type_id == 12:
        temp_sql = (
            "Select Agents.AgentNo As AuthRNo ,Agents.AgentID As AuthRID, PhoneUsers.PhonePassword, Users.UserID "
            "FROM Agents WITH (NOLOCK) "
            "INNER JOIN TelcanInternet.dbo.Users Users ON Users.AgentNo=Agents.AgentNo "
            "INNER JOIN TelcanInternet.dbo.PhoneUsers PhoneUsers ON Users.RecordID=PhoneUsers.RecordID "
            f"WHERE ( ResellerID={_safe_sql_text(reseller_id)} AND CallerID='{_safe_sql_text(checked_ani)}' )"
        )
        i_auth_user_type = 3
    else:
        temp_sql = (
            "Select Clients.ClientNo As AuthRNo ,Clients.ClientID As AuthRID, PhoneUsers.PhonePassword, Users.UserID "
            "From Clients WITH (NOLOCK) INNER JOIN Agents WITH (NOLOCK) ON Clients.AgentID=Agents.AgentID "
            "INNER JOIN TelcanInternet.dbo.Users Users ON Users.ClientNo=Clients.ClientNo "
            "INNER JOIN TelcanInternet.dbo.PhoneUsers PhoneUsers ON Users.RecordID=PhoneUsers.RecordID "
            f"WHERE ( ResellerID={_safe_sql_text(reseller_id)} AND CallerID='{_safe_sql_text(checked_ani)}' )"
        )
        i_auth_user_type = 2

    rows = _fetch_all(temp_sql, "TelcanAccounts")
    if not rows:
        i_auth_type_id = 1
        result = "Request for Account ID (ClientID or AgentID)"
    elif len(rows) > 1:
        i_auth_type_id = 1
        result = "More than 1 account attached with ANI, Request for Account ID (ClientID or AgentID)"
    else:
        row = rows[0]
        auth_rid = str(row.get("AuthRID") or "")
        auth_rno = str(row.get("AuthRNo") or "")
        auth_user_id = str(row.get("UserID") or "")
        phone_password = str(row.get("PhonePassword") or "")
        if phone_password.strip() == "":
            i_auth_type_id = 3
            result = f"ANI matched with {auth_rno} ,Password empty, Caller authenticated"
        else:
            i_auth_type_id = 2
            result = f"ANI matched with {auth_rno} ,Password required for authentication"

    payload = {
        "PhonePassword": phone_password,
        "AuthTypeID": i_auth_type_id,
        "AuthUserID": auth_user_id,
        "AuthRNo": auth_rno,
        "AuthRID": auth_rid,
        "AuthUserType": i_auth_user_type,
    }
    return temp_result_id, payload, result


async def _handle_get_inbound_line_info_v405(request: Request, endpoint: str, _: BackgroundTasks) -> JSONResponse:
    try:
        dnis_raw = _param(request, "DNIS").strip()
        ani = _param(request, "ANI").strip()
        ani2 = _param(request, "ANI2").strip()
        current_server_ip = _param(request, "IP").strip()
        origin_ip = _param(request, "OriginIP").strip()
        if not current_server_ip:
            current_server_ip = (request.client.host if request.client else "") or ""

        dnis, original_dnis = _normalize_dnis_v405(dnis_raw)

        call_type_id = 0
        line_type_id = 0
        p_rate_category_id: Any = 0
        result_id = 0
        result = "Successful"
        client_id: Any = 0
        client_no: Any = "INVALID"
        line_reseller_no: Any = "INVALID"
        line_no: Any = ""
        line_reseller_id: Any = 0
        provider_id: Any = 0
        formatted_line_no = ""
        dial_plan_id: Any = 0
        b_payphone_allowed = True
        reseller_no = ""
        always_ask_for_pin = False
        b_access_number = False

        app_name = f"TELCAN_AST_CCM_1.0_{current_server_ip}"
        cts_queue_id = _create_cts_queue_id_v2(dnis, ani, app_name)
        payload: dict[str, Any] = {"CTSQueueID": cts_queue_id, "QueueID": cts_queue_id}

        if dnis and _is_int(dnis):
            sql = f"EXEC spGetInboundLineInfo4 @LineNo='{_safe_sql_text(dnis)}'"
            row = _fetch_one(sql, "TelcanAccounts")
            if row:
                call_type_id = _to_int(row.get("CallTypeID"), 0)
                always_ask_for_pin = _boolish(row.get("AlwaysAskForPIN"))
                reseller_no = str(row.get("ResellerNo") or "")
                result_id = _to_int(row.get("ResultID"), 0)
                if str(result_id) == "1":
                    result_id = 0
                    b_access_number = True
                for k, v in row.items():
                    ku = str(k).upper()
                    if ku in {"RESULTID", "CALLTYPEID", "LINENO", "RESELLERNO"}:
                        continue
                    payload[k] = v
                result = "Access Number"
            else:
                result_id = 2

            sql = (
                "Select Resellers.ResellerNo,Resellers.ResellerID, Clients.ClientNo,Clients.ClientID, "
                "Lines.[LineNo], Lines.FormatedLineNo, Lines.LineTypeID, F_VPBX, Lines.ProviderID, Lines.ServerIP, Lines.DialPlanID, Lines.PayPhone "
                "FROM Lines WITH (NOLOCK) INNER JOIN Clients WITH (NOLOCK) ON Lines.ClientID=Clients.CLientID "
                "INNER JOIN Agents WITH (NOLOCK) ON Agents.AgentID=Clients.AgentID "
                "INNER JOIN Resellers WITH (NOLOCK) ON Resellers.ResellerID=Agents.ResellerID "
                f"WHERE [LineNo]={_safe_sql_text(dnis)}"
            )
            row = _fetch_one(sql, "TelcanAccounts")
            if row:
                line_no = row.get("LineNo", "")
                line_type_id = _to_int(row.get("LineTypeID"), 0)
                client_no = row.get("ClientNo", "INVALID")
                client_id = row.get("ClientID", 0)
                line_reseller_no = row.get("ResellerNo", "INVALID")
                if not reseller_no:
                    reseller_no = str(line_reseller_no)
                line_reseller_id = row.get("ResellerID", 0)
                formatted_line_no = str(row.get("FormatedLineNo") or "")
                provider_id = row.get("ProviderID", 0)
                dial_plan_id = row.get("DialPlanID", 0)
                b_payphone_allowed = _boolish(row.get("PayPhone"))
                payload["VPBX"] = 1 if _to_int(row.get("F_VPBX"), 0) > 0 else 0
                if str(result_id) == "2":
                    result = "System DID"
                    result_id = 0

            if not _is_int(dial_plan_id):
                dial_plan_id = 0
            if _to_int(dial_plan_id, 0) != 0:
                payload["DialPlanID"] = dial_plan_id
                sql = (
                    "EXEC spGetDialPlan "
                    f"@TelNo='{_safe_sql_text(ani)}', @DialPlanID={_safe_sql_text(dial_plan_id)}, "
                    f"@ClientNo='{_safe_sql_text(client_no)}', @Outbound=0 ;"
                )
                row = _fetch_one(sql, "TelcanAccounts")
                if row and row.get("TelNo") is not None:
                    ani = str(row.get("TelNo"))
            else:
                if formatted_line_no[:1] == "1" and ani[:1] != "0" and _is_int(ani) and len(ani) == 10:
                    ani = f"1{ani}"

            if not _is_int(provider_id):
                provider_id = 0
            sql = (
                "EXEC spGetProviderRateID "
                f"@ProviderID={_safe_sql_text(provider_id)}, @IPAddress='{_safe_sql_text(origin_ip)}'"
            )
            row = _fetch_one(sql, "TelcanLCR")
            if row:
                p_rate_category_id = row.get("PRateCategoryID", 0)
                provider_id = row.get("ProviderID", provider_id)

            if _is_tollfree_no(formatted_line_no) and _is_payphone_ani2(ani2) and (not b_payphone_allowed):
                result = "Pay Phone Not Allowed"
                result_id = 2

            if str(result_id) == "0":
                if call_type_id == 1:
                    result_id, ani, result = _trigger_callback_v405(dnis, ani, str(reseller_no), always_ask_for_pin, True)
                elif call_type_id == 17:
                    result_id, ani, result = _trigger_callback_v405(dnis, ani, str(reseller_no), always_ask_for_pin, False)
                elif call_type_id in {12, 15}:
                    tmp_res, auth_payload, auth_result = _get_authentication_v405(ani, call_type_id, str(line_reseller_id))
                    result_id = tmp_res
                    result = auth_result
                    payload.update(auth_payload)
                elif str(result_id) == "1":
                    result_id = 0

        if str(result_id) != "0":
            dnis = original_dnis

        payload.update(
            {
                "DNIS": dnis,
                "ANI": ani,
                "ResellerNo": reseller_no,
                "LineNo": line_no,
                "InboundTypeID": call_type_id,
                "LineTypeID": line_type_id,
                "LineResellerNo": line_reseller_no,
                "ProviderID": provider_id,
                "PRateCategoryID": p_rate_category_id,
                "ResultID": result_id,
                "ClientID": client_id,
                "ClientNo": client_no,
                "Result": result,
            }
        )
        return _json_response(payload)
    except Exception as exc:
        return _db_error(endpoint, exc)


def _fix_telno_for_int_asterisk(tel_no: str) -> str:
    t = str(tel_no or "")
    if (not t.startswith("1")) and (not t.startswith("011")) and t != "0":
        return f"011{t}"
    return t


async def _handle_asterisk_lookup_v2(request: Request, endpoint: str, _: BackgroundTasks) -> JSONResponse:
    try:
        dialout_no = _param(request, "dialoutno").strip()
        callsource = _param(request, "callsource").strip()
        device_user_id_inbound = _param(request, "DeviceUserIDInbound").strip() or "0"
        application_name = _param(request, "ApplicationName").strip() or "AsteriskLookUp.asp"

        try:
            call_src = int(callsource)
        except Exception:
            call_src = 99

        process_call = 0
        process_desc = "Call failed"
        device_user_id = 1
        internal_dialout_no = ""
        line_no: Any = 0
        dialin_no = ""

        call_from = device_user_id_inbound
        call_to = dialout_no

        row_from = _fetch_one(f"EXEC spVoipGetLineNo '{_safe_sql_text(call_from)}', @CheckBalance=0 ", "TelcanAccounts") or {}
        if call_src == 1 and str(row_from.get("Status") or "") == "Active":
            dp_sql = (
                "EXEC spGetDialPlan "
                f"@ClientNo='{_safe_sql_text(row_from.get('ClientNo', ''))}', "
                f"@ClientID={_safe_sql_text(row_from.get('ClientID', 0))}, "
                f"@LineNo='{_safe_sql_text(row_from.get('LineNo', 0))}', "
                f"@TelNo='{_safe_sql_text(call_to)}', "
                f"@DialPlanID={_safe_sql_text(row_from.get('DialPlanID', 0))}, "
                f"@AreaCode='{_safe_sql_text(row_from.get('AreaCode', ''))}', "
                f"@VirtualDID={'1' if _boolish(row_from.get('VirtualDID')) else '0'}"
            )
            row_dp = _fetch_one(dp_sql, "TelcanAccounts")
            if row_dp and row_dp.get("TelNo") is not None:
                call_to = str(row_dp.get("TelNo"))

        row_to = _fetch_one(f"EXEC spVoipGetLineNo '{_safe_sql_text(call_to)}', @CheckBalance=0", "TelcanAccounts") or {}
        if _to_int(row_to.get("LineTypeId"), 0) == 6:
            fm_sql = f"EXEC spFollowMePINfromANI '{_safe_sql_text(call_to)}', '{_safe_sql_text(call_from)}'"
            row_fm = _fetch_one(fm_sql, "TelcanAccounts") or {}
            fm_line = str(row_fm.get("LineNo") or "")
            if fm_line:
                call_to = fm_line
                row_to = _fetch_one(f"EXEC spVoipGetLineNo '{_safe_sql_text(call_to)}'", "TelcanAccounts") or row_to

        call_from_lineno = str(row_from.get("LineNo") or "0")
        call_to_lineno = str(row_to.get("LineNo") or "0")
        call_from_status = str(row_from.get("Status") or "")
        call_to_status = str(row_to.get("Status") or "")
        call_from_status_id = str(row_from.get("StatusID") or "0")
        call_to_status_id = str(row_to.get("StatusID") or "0")
        call_from_type = str(row_from.get("Type") or "")
        call_to_type = str(row_to.get("Type") or "")
        call_from_formatted = str(row_from.get("OutgoingCallerID") or "")
        call_to_formatted = str(row_to.get("OutgoingCallerID") or "")

        b_valid_call = True
        process_desc = f"Call From: {call_from_type} To: {call_to_type}"
        if call_src == 0:
            call_from_status_id = "0"
            line_no = call_to_lineno
            if call_from_type == "PRI":
                dialin_no = call_from
            elif call_from_type in {"DEVICE", "LINE"}:
                dialin_no = call_from_formatted
            else:
                dialin_no = call_from_lineno
            if call_to_type in {"DEVICE", "LINE"}:
                dialout_no = call_to_formatted
            else:
                dialout_no = call_to
        else:
            line_no = call_from_lineno
            if call_to_type == "PRI":
                dialout_no = _fix_telno_for_int_asterisk(call_to)
            elif call_to_type in {"DEVICE", "LINE"}:
                dialout_no = call_to_formatted
            else:
                dialout_no = call_to_lineno
            if call_from_type in {"DEVICE", "LINE"}:
                dialin_no = call_from_formatted
            else:
                dialin_no = call_from

        if call_from_lineno == "0" and call_to_lineno == "0":
            b_valid_call = False
        if call_src == 0 and call_to_status_id != "0":
            b_valid_call = False
        if call_src == 1 and call_from_status_id != "0":
            b_valid_call = False

        if b_valid_call:
            process_call = 1
            process_desc = f"{process_desc} Status:Ok"
        else:
            process_call = 0
            process_desc = f"{process_desc} Status:Failed"

        if call_to_lineno != "0":
            device_user_id = _to_int(row_to.get("DeviceUserID"), 0)
            if device_user_id != 1:
                internal_dialout_no = call_to_lineno
        else:
            device_user_id = 1

        cts_sql = (
            "EXEC spSetCTSQueue "
            f"@DNIS='{_safe_sql_text(line_no)}',@ANI='{_safe_sql_text(device_user_id_inbound)}',"
            f"@Description='{_safe_sql_text(process_desc)}',@ApplicationName='{_safe_sql_text(application_name)}'"
        )
        cts_row = _fetch_one(cts_sql, "TelcanSQLLogs") or {}
        cts_queue_id = cts_row.get("CTSQueueID", 0)

        payload: dict[str, Any] = {
            "ProcessCall": process_call,
            "ProcessCallDes": process_desc,
            "DeviceUserID": device_user_id,
            "dialoutNo": internal_dialout_no or dialout_no,
            "dialinNo": dialin_no,
            "CallFromStatus": call_from_status,
            "CallToStatus": call_to_status,
            "CTSQueueID": cts_queue_id,
        }
        return _json_response(payload)
    except Exception as exc:
        return _db_error(endpoint, exc)


def _legacy_cdr_field_value(field_name: str, raw_value: str) -> str:
    name_u = field_name.upper()
    value = str(raw_value or "")
    if name_u == "VOICEMAILID":
        value = str(_to_int(value, 0))
    if name_u == "LEG2TELNO":
        value = value.lower().replace("device/", "")
    if (not value) and name_u == "LEG1VOICEPORT":
        value = "SaveCDR.asp"

    if name_u in _CDR_NON_NUMERIC_FIELDS:
        return f"'{_safe_sql_text(value)}'"

    if name_u in _CDR_BOOLEAN_FIELDS:
        return "1" if _boolish(value) else "0"

    if not value:
        return "0"
    if _is_number(value):
        return value
    return "0"


def _legacy_call_duration_seconds(
    billing_interval: str,
    leg1_duration: str,
    leg2_duration: str,
    charge_leg1: str,
) -> int:
    b = _to_int(billing_interval, 0)
    l1 = _to_int(leg1_duration, 0)
    l2 = _to_int(leg2_duration, 0)
    if _boolish(charge_leg1):
        return max(l1 * b, l2 * b)
    return l2 * b


async def _handle_get_inbound_line_info_v403(request: Request, endpoint: str, bg: BackgroundTasks) -> JSONResponse:
    return await _handle_get_inbound_line_info_v405(request, endpoint, bg)


async def _handle_conference_lookup(request: Request, endpoint: str, _: BackgroundTasks, include_type: bool) -> JSONResponse:
    dnis = _param(request, "DNIS").strip()
    pin = _param(request, "PIN").strip()
    if not dnis or not pin:
        return _json_response({"ResultId": 0, "ResultStr": "DNIS and PIN are required values", "Endpoint": endpoint})

    try:
        sql = (
            "SELECT Conference.*, ISNULL(LineFeatures.Recording, 0) AS Recording "
            "FROM Conference WITH (NOLOCK) "
            "LEFT JOIN LineFeatures ON Conference.[LineNo] = LineFeatures.[LineNo] "
            f"WHERE (AdminPIN = '{_safe_sql_text(pin)}' OR PrivatePIN = '{_safe_sql_text(pin)}' OR PublicPIN = '{_safe_sql_text(pin)}') "
            "AND [Active]=1 "
            "AND GetUtcDate() >= DateAdd(n,-10,GMTStartTime) "
            "AND GetUtcDate() <= DateAdd(n,-1,GMTEndTime)"
        )
        rows = _fetch_all(sql, "TelcanAccounts")
        if len(rows) != 1:
            return _json_response({"Process": 0, "Endpoint": endpoint})

        row = rows[0]
        admin_pin = str(row.get("AdminPIN") or "")
        is_admin = admin_pin == pin
        can_speak = True if is_admin else _boolish(row.get("CanSpeak"))
        is_recorded = _boolish(row.get("Recording")) if is_admin else False
        max_duration = 60 if _boolish(row.get("Recording")) else 120

        payload: dict[str, Any] = {
            "Process": 1,
            "IsAdmin": is_admin,
            "CanSpeak": can_speak,
            "ConferenceId": row.get("ConferenceId", ""),
            "AdminPIN": row.get("AdminPIN", ""),
            "ClientId": row.get("ClientId", ""),
            "LineNo": row.get("LineNo", ""),
            "GMTStartTime": row.get("GMTStartTime", ""),
            "GMTEndTime": row.get("GMTEndTime", ""),
            "MaxCallers": row.get("NoOfCallers", ""),
            "MusicOnHold": row.get("MusicOnHold", ""),
            "WaitForAdmin": row.get("WaitForAdmin", ""),
            "EndWithAdmin": row.get("EndWithAdmin", ""),
            "AnnounceUsers": row.get("AnnounceUsers", ""),
            "IsRecorded": is_recorded,
            "MaxDuration": max_duration,
            "QuietMode": row.get("QuietMode", ""),
            "AnnounceCount": row.get("AnnounceCount", ""),
            "AnnounceUser": row.get("AnnounceUser", ""),
            "Endpoint": endpoint,
        }
        if include_type:
            conf_ring_group = _to_int(row.get("ConfRingGroupID"), 0)
            payload["ConferenceType"] = 2 if (is_admin and conf_ring_group > 0) else (1 if is_admin else 0)
        return _json_response(payload)
    except Exception as exc:
        return _db_error(endpoint, exc)


async def _handle_conference_lookup_main(request: Request, endpoint: str, bg: BackgroundTasks) -> JSONResponse:
    return await _handle_conference_lookup(request, endpoint, bg, include_type=True)


async def _handle_conference_lookup_dev(request: Request, endpoint: str, bg: BackgroundTasks) -> JSONResponse:
    return await _handle_conference_lookup(request, endpoint, bg, include_type=False)


async def _handle_log_lcr_attempt(request: Request, endpoint: str, _: BackgroundTasks) -> JSONResponse:
    queue_id = _param(request, "queueid").strip()
    lcr_id = _param(request, "lcrid").strip()
    result = _param(request, "result").strip()
    switch_ip = _param(request, "switchip").strip()
    lb_ip = _param(request, "loadbalancerip").strip()
    dialed = _param(request, "dialednumber").strip()
    try:
        if _is_int(queue_id) and _is_int(lcr_id):
            sql = (
                "INSERT INTO LCRAttempts (QueueID,LCRID,Result,SwitchIP,LoadBalancerIP,DialedNumber) "
                f"VALUES ({_safe_sql_text(queue_id)},{_safe_sql_text(lcr_id)},"
                f"'{_safe_sql_text(result)}','{_safe_sql_text(switch_ip)}','{_safe_sql_text(lb_ip)}','{_safe_sql_text(dialed)}')"
            )
            _execute(sql, "TelcanCalls_NYDB6")
        return _json_response({"ResultID": 1, "Endpoint": endpoint})
    except Exception as exc:
        return _db_error(endpoint, exc)


async def _handle_remove_monitor_id(request: Request, endpoint: str, _: BackgroundTasks) -> JSONResponse:
    monitor_id = _param(request, "MonitorID").strip()
    if not _is_int(monitor_id):
        return _json_response({"ResultID": -1, "Endpoint": endpoint})
    try:
        sql = f"EXECUTE spMon_RemoveMonitorID @MonitorID={_safe_sql_text(monitor_id)}"
        _execute(sql, "TelcanMonitor")
        return _json_response({"ResultID": 1, "Endpoint": endpoint})
    except Exception as exc:
        return _db_error(endpoint, exc)


async def _handle_synch_telcan_voip(request: Request, endpoint: str, _: BackgroundTasks) -> JSONResponse:
    query = _param(request, "query").strip()
    caller_ip = _param(request, "caller_ip").strip()
    if not caller_ip:
        caller_ip = (request.client.host if request.client else "") or ""
    query_l = query.lower()
    bad_ip_marker = "switch_ip = '10.2.:"
    allowed = (
        (
            query_l.startswith("update sip_buddies")
            or query_l.startswith("insert into sip_buddies")
            or query_l.startswith("delete from sip_buddies")
        )
        and ("where" in query_l or query_l.startswith("insert into sip_buddies"))
        and bad_ip_marker not in query_l
    )
    run_result = 0
    try:
        if allowed and query:
            run_result = 1 if _execute(query, "TelcanSwitch") >= 0 else 0
            _execute(
                "INSERT INTO replication_log (query, run_result, caller_ip) "
                f"VALUES('{_safe_sql_text(query)}', {run_result}, '{_safe_sql_text(caller_ip)}')",
                "TelcanSwitch",
            )
        return _json_response({"ResultID": run_result, "Endpoint": endpoint})
    except Exception as exc:
        return _db_error(endpoint, exc)


async def _handle_synch_telcan_voip_async(request: Request, endpoint: str, background_tasks: BackgroundTasks) -> JSONResponse:
    query = _param(request, "query").strip()
    caller_ip = (request.client.host if request.client else "") or ""
    target = f"{_private_base_url(request)}/VPBX/SynchTelcanVoIP.asp?query={quote_plus(query)}&caller_ip={quote_plus(caller_ip)}"
    background_tasks.add_task(_fire_and_forget, target)
    return _json_response({"ResultID": 1, "Endpoint": endpoint, "ForwardTo": "SynchTelcanVoIP.asp"})


async def _handle_voip_caller_id_get_by_user_id(request: Request, endpoint: str, _: BackgroundTasks) -> JSONResponse:
    user_id = _param(request, "UserID").strip()
    line_no = ""
    ext_no = ""
    try:
        if user_id:
            if "@" in user_id:
                conf_id = user_id.split("@", 1)[0]
                sql = (
                    "SELECT ISNULL(NULLIF(Lines.CallBackNo4, ''), Conference.[LineNo]) AS CallerID "
                    "FROM Conference INNER JOIN Lines ON Lines.[LineNo] = Conference.[LineNo] "
                    f"WHERE ISNULL(NULLIF(WebConferenceId, ''), CAST(ConferenceID AS VARCHAR)) = '{_safe_sql_text(conf_id)}'"
                )
                row = _fetch_one(sql, "TelcanAccounts") or {}
                line_no = str(row.get("CallerID") or "")
            else:
                user_id = user_id.split("_dial_", 1)[0]
                sql = (
                    "SELECT ISNULL([LineNo], '') AS [LineNo], ISNULL(ExtNo, '') AS ExtNo "
                    "FROM TelcanInternet.dbo.Users WITH (NOLOCK) "
                    f"WHERE UserID = '{_safe_sql_text(user_id)}'"
                )
                row = _fetch_one(sql, "TelcanAccounts") or {}
                line_no = str(row.get("LineNo") or "")
                ext_no = str(row.get("ExtNo") or "")
                if ext_no:
                    line_no = f"{line_no}_{ext_no}"
        return _json_response({"ResultID": line_no or "0", "LineNo": line_no, "Endpoint": endpoint})
    except Exception as exc:
        return _db_error(endpoint, exc)


async def _handle_sms_notification_queue(request: Request, endpoint: str, bg: BackgroundTasks) -> JSONResponse:
    return await _handle_vm_indicator_get(request, endpoint, bg)


async def _handle_voip_call_monitor(request: Request, endpoint: str, _: BackgroundTasks) -> JSONResponse:
    try:
        max_per_ani = 10
        max_overall = 30
        ani = _param(request, "ani").strip().replace("'", "''").split(":", 1)[0]
        dnis = _param(request, "dnis").strip().replace("'", "''")
        channel_id = _param(request, "CallChannelID").strip().replace("'", "''")
        caller_ip = _param(request, "CallerIP").strip().replace("'", "''")
        context = _param(request, "Context").strip().replace("'", "''") or "kamailio"
        sip_id = _param(request, "SipID").strip().replace("'", "''")
        extra_info = _param(request, "ExtraInfo").strip().replace("'", "''")
        call_type = _param(request, "CallType").strip().replace("'", "''") or "0"
        leg1_sip_call_id = _param(request, "Leg1SipCallID").strip().replace("'", "''")
        debug = _param(request, "Debug").strip()
        reg_server_ip = (request.client.host if request.client else "") or ""

        sql = (
            "SELECT TOP 1 ISNULL(NULLIF(ClientDevices.E911LineNo, 0), Lines.[LineNo]) AS CallerID, "
            "(CASE WHEN ISNULL(LSA2.Status, '') = 'OK' THEN 1 ELSE 0 END) AS E911Provisioned, "
            "ISNULL(LSA2.Country, '') AS Country, LSA2.E911ProviderID "
            "FROM TelcanSwitch.dbo.sip_buddies WITH (NOLOCK) "
            "INNER JOIN Lines WITH (NOLOCK) ON Lines.[LineNo] = ISNULL(sip_buddies.linenumber, LEFT(name, 10)) "
            "INNER JOIN Clients WITH (NOLOCK) ON Clients.ClientID = Lines.ClientID "
            "INNER JOIN Agents WITH (NOLOCK) ON Agents.AgentID = Clients.AgentID "
            "LEFT JOIN LineServiceAddress WITH (NOLOCK) ON LineServiceAddress.[LineNo] = Lines.[LineNo] "
            "LEFT JOIN LineMacs WITH (NOLOCK) ON LineMacs.SipUserID = sip_buddies.name "
            "LEFT JOIN ClientDevices WITH (NOLOCK) ON ClientDevices.Mac = LineMacs.MAC "
            "LEFT JOIN LineServiceAddress LSA2 WITH (NOLOCK) ON LSA2.[LineNo] = ISNULL(NULLIF(ClientDevices.E911LineNo, 0), Lines.[LineNo]) "
            f"WHERE (sip_buddies.name = '{_safe_sql_text(ani)}' OR (LEFT(sip_buddies.name, 10) = '{_safe_sql_text(ani)}' AND '{_safe_sql_text(context)}' = 'kamailio')) "
            "AND switch_ip <> '64.34.222.206' "
            "AND Clients.InternetUnauthorized = 0 "
            "AND LEFT(Lines.[LineNo], 3) NOT IN ('800', '833', '844', '855', '866', '877', '888') "
            "AND (LineServiceAddress.[LineNo] IS NOT NULL)"
        )
        row = _fetch_one(sql, "TelcanAccounts") or {}

        result_id = "0"
        e911 = "0"
        if row:
            result_id = str(row.get("CallerID") or "").strip()
            lcr = str(row.get("E911ProviderID") or "").strip()
            if lcr == "0":
                lcr = "044" if str(row.get("Country") or "").upper() == "USA" else "185"
            if len(lcr) == 1:
                lcr = f"00{lcr}"
            elif len(lcr) == 2:
                lcr = f"0{lcr}"
            result_id = f"{result_id}:{lcr}#"
            e911 = str(row.get("E911Provisioned") or "0").strip()

        dnis = dnis.replace("154#", "").replace("185#", "").replace("204#", "")
        if result_id != "0" and dnis == "911":
            guard_sql = (
                "SELECT COUNT(*) AS RecCount, ISNULL(SUM(CASE WHEN ANI = "
                f"'{_safe_sql_text(ani)}' THEN 1 ELSE 0 END), 0) AS RecCountPerANI "
                "FROM VoIPCallMonitor WITH (NOLOCK) "
                "WHERE DialTime > DATEADD(s,0,DATEADD(dd, DATEDIFF(dd,0,getdate()),0)) "
                "AND DNIS = '911' AND ResultID = 1"
            )
            guard = _fetch_one(guard_sql, "TelcanMonitor") or {}
            if _to_int(guard.get("RecCountPerANI"), 0) > max_per_ani or _to_int(guard.get("RecCount"), 0) > max_overall:
                result_id = "0"

        result_id_to_log = "0"
        if result_id != "0":
            if context == "kamailio":
                result_id_to_log = "2"
                result_id = "1"
            elif context == "outbound":
                result_id_to_log = "3"

        if debug != "1":
            insert_sql = (
                "INSERT INTO VoIPCallMonitor "
                "(RegServerIP, CallChannelID, CallerIP, ANI, DNIS, ResultID, Context, SipID, ExtraInfo, Leg1SipCallID, CallType) "
                f"VALUES ('{_safe_sql_text(reg_server_ip)}', '{_safe_sql_text(channel_id)}', '{_safe_sql_text(caller_ip)}', "
                f"'{_safe_sql_text(ani)}', '{_safe_sql_text(dnis)}', {_safe_sql_text(result_id_to_log)}, '{_safe_sql_text(context)}', "
                f"'{_safe_sql_text(sip_id)}', '{_safe_sql_text('E911Provisioned:' + e911 + extra_info + '; ' + result_id)}', "
                f"'{_safe_sql_text(result_id + leg1_sip_call_id)}', {_safe_sql_text(call_type)})"
            )
            _execute(insert_sql, "TelcanMonitor")

        return _json_response({"ResultID": result_id, "Endpoint": endpoint})
    except Exception as exc:
        return _db_error(endpoint, exc)


async def _handle_voip_ext_info_get(request: Request, endpoint: str, _: BackgroundTasks) -> JSONResponse:
    try:
        inphonenum = _param(request, "inphonenum").strip()
        direction = _param(request, "direction").strip()
        insipheader = _param(request, "insipheader").strip()
        callerid = _param(request, "callerid").strip()
        serverip = _param(request, "serverip").strip()
        channel = _param(request, "Channel").strip()
        context = _param(request, "Context").strip()
        sip_call_id = _param(request, "SipCallID").strip()

        peer_ext = inphonenum if direction == "0" else callerid
        line_no_from_peer = ""
        ext_no_from_peer = ""

        outphonenum = ""
        mohid = ""
        outsipheader = ""
        isanswer = ""
        isall = ""
        outcallerid = ""
        wait = ""
        number_prefix = ""
        dial_server = ""
        current_reg_ip = ""
        outcodec = ""

        if direction != "0":
            if inphonenum.startswith("*") and inphonenum != "*8" and inphonenum != "*0" and len(inphonenum) == 3:
                host_col = "VMailServer"
            else:
                host_col = "ProcessServer1st" if random.randint(1, 2) == 1 else "ProcessServer2nd"
            sip_proxy_sql = (
                "SELECT TOP 1 p.HostIP FROM SipProxyIPs r WITH (NOLOCK) "
                f"INNER JOIN SipProxyIPs p WITH (NOLOCK) ON p.RecID = r.{host_col} "
                f"WHERE r.HostIP = '{_safe_sql_text(serverip)}'"
            )
            row = _fetch_one(sip_proxy_sql, "TelcanSwitch") or {}
            if row:
                dial_server = f"@{row.get('HostIP')}"
                number_prefix = "Sip/"
                outphonenum = inphonenum

            if "_" in inphonenum:
                arr = inphonenum.split("_", 1)
                outcallerid = arr[0]
                outphonenum = arr[1]
                if "_" in callerid:
                    outcallerid = f"{outcallerid}_{callerid.split('_', 1)[1]}"

            if inphonenum in {"711", "911"}:
                monitor_url = (
                    f"{_private_base_url(request)}/VPBX/VoIPCallMonitor.asp"
                    f"?ani={quote_plus(callerid)}&dnis={quote_plus(inphonenum)}"
                    f"&CallChannelID={quote_plus(channel)}&CallerIP={quote_plus(serverip)}"
                    f"&Context={quote_plus(context)}&SipID={quote_plus(sip_call_id)}"
                )
                monitor_result = ""
                try:
                    async with httpx.AsyncClient(timeout=4.0) as client:
                        resp = await client.get(monitor_url)
                        try:
                            monitor_result = str((resp.json() or {}).get("ResultID") or "")
                        except Exception:
                            monitor_result = resp.text.strip()
                except Exception:
                    monitor_result = ""
                if monitor_result != "1":
                    isanswer = "-1"

            reg_sql = f"SELECT ISNULL(switch_ip, '') AS CurrentRegIP FROM sip_buddies WHERE name = '{_safe_sql_text(callerid)}'"
            row = _fetch_one(reg_sql, "TelcanSwitch") or {}
            current_reg_ip = str(row.get("CurrentRegIP") or "")

        if insipheader and ("Jitsi-Conference-Room" in insipheader):
            user_id = insipheader.split(",", 1)[0].split(":", 1)[-1].strip()
            user_id = user_id.split("_dial_", 1)[0]
            user_sql = (
                "SELECT ISNULL([LineNo], '') AS [LineNo], ISNULL(ExtNo, '') AS ExtNo "
                "FROM TelcanInternet.dbo.Users WITH (NOLOCK) "
                f"WHERE UserID = '{_safe_sql_text(user_id)}'"
            )
            row = _fetch_one(user_sql, "TelcanAccounts") or {}
            line_no_from_user = str(row.get("LineNo") or "")
            ext_no_from_user = str(row.get("ExtNo") or "")
            if ext_no_from_user:
                line_no_from_user = f"{line_no_from_user}_{ext_no_from_user}"
            outcallerid = line_no_from_user

        if peer_ext and (not inphonenum.startswith("*")):
            arr = peer_ext.split("_", 1)
            line_no_from_peer = arr[0]
            ext_no_from_peer = arr[1] if len(arr) > 1 else "-1"
            moh_sql = (
                "SELECT ISNULL(InCallMusicOnHoldID, 0) AS InCallMusicOnHoldID "
                f"FROM VPBXExts WHERE [LineNo] = '{_safe_sql_text(line_no_from_peer)}' "
                f"AND ExtNo = '{_safe_sql_text(ext_no_from_peer)}'"
            )
            row = _fetch_one(moh_sql, "TelcanAccounts") or {}
            mohid = str(row.get("InCallMusicOnHoldID") or "").strip()
            if mohid in {"", "0"}:
                mohid = ""
            else:
                mohid = f"/mnt/media/moh/{mohid}"

        if direction == "0" or (direction == "1" and inphonenum.startswith("*")):
            item_id = peer_ext if direction == "0" else outphonenum
            cf_sql = (
                "SELECT ISNULL(CallForwardTo, '') AS CallForwardTo, ISNULL(FailOVerTo, '') AS FailOVerTo, "
                "ISNULL(AppData, '') AS AppData FROM CallForwarding WITH (NOLOCK) "
                f"WHERE CallForwardType = 25 AND '{_safe_sql_text(item_id)}' LIKE ItemID"
            )
            row = _fetch_one(cf_sql, "TelcanAccounts") or {}
            if row:
                outphonenum = str(row.get("CallForwardTo") or outphonenum)
                user_line_no = str(row.get("FailOVerTo") or "")
                app_data = str(row.get("AppData") or "")
            else:
                user_line_no = ""
                app_data = ""
            if outphonenum:
                if not user_line_no:
                    user_line_no = line_no_from_peer
                user_ext_no = ext_no_from_peer
                if user_ext_no == "-1":
                    user_ext_no = ""
                if "ExtNo:" in app_data:
                    try:
                        ext_start_from = int(app_data.split(":", 1)[1])
                        if ext_start_from <= len(user_ext_no):
                            user_ext_no = user_ext_no[ext_start_from - 1 :]
                    except Exception:
                        pass
                user_access_sql = (
                    "SELECT TOP 1 Users.UserID "
                    "FROM TelcanInternet.dbo.UserLineAccess WITH (NOLOCK) "
                    "INNER JOIN TelcanInternet.dbo.Users WITH (NOLOCK) ON UserLineAccess.RecordID = Users.RecordID "
                    f"WHERE UserLineAccess.[LineNo] = '{_safe_sql_text(user_line_no)}' "
                    f"AND UserLineAccess.ExtNo = '{_safe_sql_text(user_ext_no)}'"
                )
                row = _fetch_one(user_access_sql, "TelcanSwitch") or {}
                if row:
                    outsipheader = f"Jitsi-Conference-Room: {row.get('UserID')}"

        return _json_response(
            {
                "outphonenum": f"{number_prefix}{outphonenum}{dial_server}",
                "mohid": mohid,
                "isanswer": isanswer,
                "isall": isall,
                "outcallerid": outcallerid,
                "outsipheader": outsipheader,
                "wait": wait,
                "currentregip": current_reg_ip,
                "volumelevel": "",
                "outcodec": outcodec,
                "Endpoint": endpoint,
            }
        )
    except Exception as exc:
        return _db_error(endpoint, exc)


async def _handle_xxx_handle_crm(request: Request, endpoint: str, _: BackgroundTasks) -> JSONResponse:
    try:
        ani = _param(request, "ani").strip().replace("'", "''")
        dnis = _param(request, "dnis").strip().replace("'", "''")
        call_status = _param(request, "CallStatus").strip().replace("'", "''") or "0"
        start_time = _param(request, "StartTime").strip().replace("'", "''")
        duration = _param(request, "Duration").strip().replace("'", "''")
        recording_url = _param(request, "RecordingURL").strip().replace("'", "''")

        answered_line = ani.split("_", 1)[0] if ani else ""
        answered_ext = ani.split("_", 1)[1] if "_" in ani else "-1"

        sql = (
            "SELECT TOP 1 CRMUserID, Clients.ClientID, InstanceName, APIURL_Override, CRMTypeIDReference "
            "FROM VPBXExts WITH (NOLOCK) "
            "INNER JOIN Lines WITH (NOLOCK) ON Lines.[LineNo] = VPBXExts.[LineNo] "
            "INNER JOIN Clients WITH (NOLOCK) ON Clients.ClientID = Lines.ClientID "
            "INNER JOIN ClientCRMAPIInfo WITH (NOLOCK) ON ClientCRMAPIInfo.ClientID = Clients.ClientID AND CRMTypeIDReference IN (3) "
            f"WHERE VPBXExts.[LineNo] = '{_safe_sql_text(answered_line)}' "
            f"AND VPBXExts.ExtNo = '{_safe_sql_text(answered_ext)}' "
            "AND Clients.InternetUnauthorized = 0"
        )
        row = _fetch_one(sql, "TelcanAccounts") or {}
        result_id = "0"
        crm_url = ""
        if row and str(row.get("CRMTypeIDReference") or "") == "3":
            crm_url = str(row.get("APIURL_Override") or "").strip()
            body: dict[str, Any] = {
                "orgId": str(row.get("InstanceName") or ""),
                "userId": str(row.get("CRMUserID") or ""),
                "type": "incoming",
                "from": dnis,
                "to": ani,
            }
            if call_status == "0":
                crm_url = f"{crm_url}/call"
            elif call_status == "2":
                crm_url = f"{crm_url}/call-ends"
                body["startTime"] = start_time
                body["duration"] = duration
                body["recordUrl"] = recording_url

            async with httpx.AsyncClient(timeout=8.0) as client:
                resp = await client.post(
                    crm_url,
                    json=body,
                    headers={
                        "Content-Type": "application/json",
                        "Token": "OhSRDV7WZnz5uEJCA8sTfU4FJlc8aCw7q6BQDtAatCjHDx5v7dhDpEXaCVUhbm2M",
                    },
                )
                result_id = resp.text.strip() or "0"

        return _json_response({"ResultID": result_id, "CRMURL": crm_url, "Endpoint": endpoint})
    except Exception as exc:
        return _db_error(endpoint, exc)


async def _handle_save_cdr_v5(request: Request, endpoint: str, _: BackgroundTasks) -> JSONResponse:
    try:
        params: dict[str, str] = {str(k): str(v) for k, v in request.query_params.items()}
        if request.method == "POST":
            try:
                form = await request.form()
                for k, v in form.multi_items():
                    params[str(k)] = str(v)
            except Exception:
                pass

        assignments: list[str] = []
        for fld_name, raw in params.items():
            if fld_name.upper() not in _CDR_VALID_FIELDS:
                continue
            if fld_name.upper() in _CDR_SKIP_FIELDS:
                continue
            assignments.append(f"@{fld_name}={_legacy_cdr_field_value(fld_name, raw)}")
        sql_args = ",".join(assignments)

        cdr_id = 0
        cdr_to_update = _to_int(params.get("CDRIDToUpdate"), 0)
        if cdr_to_update > 0:
            if sql_args:
                sql_update = f"UPDATE CDR SET {sql_args.replace('@', '')} WHERE CDRID = {cdr_to_update}"
                _execute(sql_update, "TelcanCalls_NYDB6")
                _execute(sql_update, "TelcanCalls")
            cdr_id = cdr_to_update
        else:
            sql_save = f"EXEC spCDRSave2 {sql_args}".strip()
            row = _fetch_one(sql_save, "TelcanCalls_NYDB6") or {}
            cdr_id = _to_int(row.get("CDRID"), _to_int(_first_row_value(row, 0), 0))

        reseller_no = params.get("ResellerNo", "")
        line_no = params.get("LineNo", "")
        connect_status = str(params.get("ConnectStatus", "")).upper()
        reseller_cost = float(params.get("RLeg1Cost", "0") or 0) + float(params.get("RLeg2Cost", "0") or 0)
        line_cost = float(params.get("Cost", "0") or 0)

        update_balance = "Skipped"
        if cdr_id > 0 and (reseller_cost != 0 or line_cost != 0):
            upd_bal_sql = (
                f"EXEC spUpdateBalance '{_safe_sql_text(reseller_no)}',{reseller_cost},{_safe_sql_text(line_no)},{line_cost}"
            )
            _execute(upd_bal_sql, "TelcanAccounts")
            update_balance = "OK"

        call_count = "Skipped"
        save_reg_no = "Skipped"
        if connect_status == "OK":
            call_count_sql = (
                "EXEC spIncrementCompletedCallCount "
                f"@LineNo='{_safe_sql_text(line_no)}', @LinetypeID=0, "
                f"@Leg2RateCode = '{_safe_sql_text(params.get('Leg2RateCode', ''))}'"
            )
            _execute(call_count_sql, "TelcanAccounts")
            call_count = "OK"

            auto_register = params.get("AutoRegisterTypeID", "").strip()
            virtual_did = _boolish(params.get("VirtualDID", ""))
            if auto_register and _is_int(auto_register) and virtual_did:
                is_multi = 1 if _boolish(params.get("IsMultiRegNos", "")) else 0
                leg1_area = str(params.get("Leg1Area", ""))
                dnis = "0"
                if "[" in leg1_area and "]" in leg1_area:
                    dnis = leg1_area.split("[", 1)[1].split("]", 1)[0]
                    if not _is_int(dnis):
                        dnis = "0"
                save_reg_sql = (
                    "EXEC spSaveRegisteredNos "
                    f"@LineNo='{_safe_sql_text(line_no)}', "
                    f"@ClientNo='{_safe_sql_text(params.get('ClientNo', ''))}', "
                    f"@ResellerNo='{_safe_sql_text(reseller_no)}', "
                    f"@DNIS='{_safe_sql_text(dnis)}', "
                    f"@CallbackNo='{_safe_sql_text(params.get('Leg1TelNo', ''))}', "
                    f"@DestinationNo='{_safe_sql_text(params.get('Leg2TelNo', ''))}', "
                    f"@RegisterType={_safe_sql_text(auto_register)}, @IsMultiRegNos={is_multi}"
                )
                _execute(save_reg_sql, "TelcanAccounts")
                save_reg_no = "OK"

        cdr_to_delete = _to_int(params.get("CDRIDToDelete"), 0)
        if cdr_to_delete > 0:
            del_sql = f"DELETE FROM CDR WHERE CDRID = {cdr_to_delete}"
            _execute(del_sql, "TelcanCalls_NYDB6")
            _execute(del_sql, "TelcanCalls")

        leg1_tel = str(params.get("Leg1TelNo", ""))
        leg2_tel = str(params.get("Leg2TelNo", ""))
        leg1_voice_port = str(params.get("Leg1VoicePort", ""))
        if ("_" in leg1_tel or "_" in leg2_tel) and (not leg2_tel.lower().startswith("sip/")):
            call_type = (
                "outgoing"
                if leg1_voice_port == "TELCAN_AST_TO_1_247-" or ("_" in leg1_tel and "_" not in leg2_tel)
                else "incoming"
            )
            crm_url = (
                "http://10.2.69.95/VoIPConfig/HandleCRM.asp"
                f"?APIusr=callturephp&APIpwd=C2lltureT3lcan&CallStatus=2"
                f"&ani={quote_plus(leg1_tel)}&dnis={quote_plus(leg2_tel)}"
                f"&StartTime={quote_plus(str(params.get('Leg1StartGMT', '')))}"
                f"&Duration={_legacy_call_duration_seconds(params.get('BillingInterval', '0'), params.get('Leg1Duration', '0'), params.get('Leg2Duration', '0'), params.get('ChargeLeg1', '0'))}"
                f"&QueueID={quote_plus(str(params.get('QueueID', '')))}"
                f"&callType={quote_plus(call_type)}&LineNo={quote_plus(str(line_no))}"
            )
            try:
                async with httpx.AsyncClient(timeout=4.0) as client:
                    await client.post(crm_url)
            except Exception:
                pass

        return _json_response(
            {
                "CDRID": cdr_id,
                "UpdateBalance": update_balance,
                "CallCount": call_count,
                "SaveRegNo": save_reg_no,
                "Version": endpoint,
                "ResultID": 1 if cdr_id > 0 else 0,
                "Endpoint": endpoint,
            }
        )
    except Exception as exc:
        return _db_error(endpoint, exc)


async def _handle_async_forward(request: Request, sync_endpoint: str, background_tasks: BackgroundTasks) -> JSONResponse:
    url = f"{_private_base_url(request)}/VPBX/{sync_endpoint}"
    background_tasks.add_task(_fire_and_forget, url)
    return _json_response(
        {
            "ResultID": 1,
            "Message": "Async request queued",
            "ForwardTo": sync_endpoint,
            "ForwardURL": url,
        }
    )


HANDLERS: dict[str, Callable[[Request, str, BackgroundTasks], Awaitable[JSONResponse]]] = {
    "test.asp": _handle_test,
    "servicetypeget.asp": _handle_service_type_get,
    "servicetypegetv2.asp": _handle_service_type_get_v2,
    "inbounddidserveripget.asp": _handle_inbound_did_server_ip_get,
    "getcallerid.asp": _handle_get_caller_id,
    "getcallerid-dev.asp": _handle_get_caller_id,
    "getcalleridv3.asp": _handle_get_caller_id_v3,
    "providerlookupv3.asp": _handle_provider_lookup_v3,
    "getproviderinfo.asp": _handle_get_provider_info,
    "conferencelookup.asp": _handle_conference_lookup_main,
    "conferencelookup-dev.asp": _handle_conference_lookup_dev,
    "getinboundlineinfov403.asp": _handle_get_inbound_line_info_v403,
    "getinboundlineinfov405.asp": _handle_get_inbound_line_info_v405,
    "asterisklookupv2.asp": _handle_asterisk_lookup_v2,
    "getratesv301.asp": _handle_get_rates,
    "getratesv305.asp": _handle_get_rates,
    "getratesv306.asp": _handle_get_rates,
    "switchconfiggetold.asp": _handle_switch_config_get_old,
    "getlinenocount.asp": _handle_get_line_no_count,
    "callsetupv308.asp": _handle_call_setup_v308,
    "callsetupv308-dev.asp": _handle_call_setup_v308,
    "callend.asp": _handle_call_end,
    "blindtransferinfo.asp": _handle_blind_transfer_info,
    "leg2connected.asp": _handle_leg2_connected,
    "updatecallstatus.asp": _handle_update_call_status,
    "setbusy2.asp": _handle_set_busy2,
    "createfaxid.asp": _handle_create_fax_id,
    "faxlookup.asp": _handle_fax_lookup,
    "faxstatus.asp": _handle_fax_status,
    "faxstatuscheck.asp": _handle_fax_status_check,
    "faxstatusupdate.asp": _handle_fax_status_update,
    "faxstatusv2.asp": _handle_fax_status_v2,
    "vmindicatorget.asp": _handle_vm_indicator_get,
    "smsnotificationqueue.asp": _handle_sms_notification_queue,
    "transcriptionsave.asp": _handle_transcription_save,
    "voicemaildeletelist.asp": _handle_voice_mail_delete_list,
    "voicemail2.asp": _handle_voice_mail_2,
    "voipcallmonitor.asp": _handle_voip_call_monitor,
    "voipcalleridgetbyuserid.asp": _handle_voip_caller_id_get_by_user_id,
    "voipextinfoget.asp": _handle_voip_ext_info_get,
    "loglcrattempt.asp": _handle_log_lcr_attempt,
    "removemonitorid.asp": _handle_remove_monitor_id,
    "synchtelcanvoip.asp": _handle_synch_telcan_voip,
    "synchtelcanvoipasync.asp": _handle_synch_telcan_voip_async,
    "savecdrv5.asp": _handle_save_cdr_v5,
    "savecdrv5-dev.asp": _handle_save_cdr_v5,
    "xxxhandlecrm.asp": _handle_xxx_handle_crm,
    "voipdbtest.asp": _handle_voip_db_test,
    "getvpbxinfo.asp": _handle_get_vpbx_info,
    "getvpbxinfo-dev.asp": _handle_get_vpbx_info,
    "getvpbxinfo-defaultfiles.asp": _handle_get_vpbx_info,
    "getvpbxinfo106.asp": _handle_get_vpbx_info,
}


@app.get("/healthz", response_class=PlainTextResponse)
async def healthz() -> PlainTextResponse:
    return PlainTextResponse("ok\n", media_type="text/plain; charset=utf-8")


@app.api_route("/VPBX/{endpoint_name}", methods=["GET", "POST"], response_class=JSONResponse)
async def vpbx_dispatch(endpoint_name: str, request: Request, background_tasks: BackgroundTasks):
    endpoint = endpoint_name.strip()
    endpoint_l = endpoint.casefold()

    known_endpoints = _list_asp_endpoints()
    if endpoint_l == "leg2connectedasync.asp":
        return await _handle_async_forward(request, "Leg2Connected.asp", background_tasks)
    if endpoint_l == "xxxhandlecrmasync.asp":
        return await _handle_async_forward(request, "xxxHandleCRM.asp", background_tasks)

    handler = HANDLERS.get(endpoint_l)
    if handler:
        return await handler(request, endpoint, background_tasks)

    if known_endpoints:
        known_endpoint_l = {name.casefold() for name in known_endpoints}
        if endpoint_l not in known_endpoint_l:
            return _json_response({"ResultID": -1, "Error": f"Unknown endpoint {endpoint}", "Endpoint": endpoint})

    generic_payload = _try_generic_proc_endpoint(endpoint, request)
    return _json_response(generic_payload, status_code=200)
