import os
import json
import uuid
from datetime import datetime, timezone, timedelta
from urllib.parse import quote

from fastapi import FastAPI, Request, Form, HTTPException
from fastapi.staticfiles import StaticFiles
from fastapi.responses import HTMLResponse, RedirectResponse, Response
from fastapi.templating import Jinja2Templates
import qrcode
from io import BytesIO


app = FastAPI(title="Mehran Gateway")
app.mount("/static", StaticFiles(directory="static"), name="static")

templates = Jinja2Templates(directory="templates")

DATA_DIR = os.getenv("DATA_DIR", "/data")
STATE_FILE = os.path.join(DATA_DIR, "state.json")

ADMIN_PASSWORD = os.getenv("ADMIN_PASSWORD", "change-me-now")
PUBLIC_DOMAIN = os.getenv("PUBLIC_DOMAIN", "")

os.makedirs(DATA_DIR, exist_ok=True)


def load_state():
    if not os.path.exists(STATE_FILE):
        return {"configs": []}

    try:
        with open(STATE_FILE, "r", encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return {"configs": []}


def save_state(state):
    temp_file = STATE_FILE + ".tmp"

    with open(temp_file, "w", encoding="utf-8") as f:
        json.dump(
            state,
            f,
            ensure_ascii=False,
            indent=2
        )

    os.replace(temp_file, STATE_FILE)


def is_authenticated(request: Request):
    return request.cookies.get("admin_auth") == "ok"


def require_auth(request: Request):
    if not is_authenticated(request):
        raise HTTPException(
            status_code=401,
            detail="Unauthorized"
        )


def create_vless_link(config):

    params = []

    if config.get("security") == "tls":
        params.append(("security", "tls"))

        if config.get("sni"):
            params.append(("sni", config["sni"]))

    if config.get("type"):
        params.append(("type", config["type"]))

    if config.get("path"):
        params.append(("path", config["path"]))

    if config.get("host"):
        params.append(("host", config["host"]))

    query = "&".join(
        f"{quote(str(key))}={quote(str(value), safe='/:?=&')}"
        for key, value in params
        if value
    )

    return (
        f'vless://'
        f'{config["uuid"]}@'
        f'{config["server"]}:'
        f'{config["port"]}'
        f'?{query}'
        f'#{quote(config["name"])}'
    )


@app.get("/", response_class=HTMLResponse)
def dashboard(request: Request):

    if not is_authenticated(request):
        return RedirectResponse("/login")

    state = load_state()

    return templates.TemplateResponse(
        "dashboard.html",
        {
            "request": request,
            "configs": state["configs"],
            "domain": PUBLIC_DOMAIN
        }
    )


@app.get("/login", response_class=HTMLResponse)
def login_page(request: Request):

    return templates.TemplateResponse(
        "login.html",
        {
            "request": request
        }
    )


@app.post("/login")
def login(password: str = Form(...)):

    if password != ADMIN_PASSWORD:
        return RedirectResponse(
            "/login?error=1",
            status_code=303
        )

    response = RedirectResponse(
        "/",
        status_code=303
    )

    response.set_cookie(
        "admin_auth",
        "ok",
        httponly=True,
        secure=True,
        samesite="lax"
    )

    return response


@app.get("/logout")
def logout():

    response = RedirectResponse(
        "/login",
        status_code=303
    )

    response.delete_cookie("admin_auth")

    return response


@app.post("/configs")
def create_config(
    request: Request,

    name: str = Form(...),

    server: str = Form(...),

    port: int = Form(443),

    uuid_value: str = Form(""),

    path: str = Form("/"),

    host: str = Form(""),

    sni: str = Form(""),

    security: str = Form("tls"),

    days: int = Form(30)
):

    require_auth(request)

    state = load_state()

    config_uuid = (
        uuid_value.strip()
        if uuid_value.strip()
        else str(uuid.uuid4())
    )

    expiration = (
        datetime.now(timezone.utc)
        + timedelta(days=max(0, days))
    )

    config = {

        "id": str(uuid.uuid4()),

        "name": name.strip()[:80],

        "server": server.strip(),

        "port": int(port),

        "uuid": config_uuid,

        "path": path.strip() or "/",

        "host": host.strip(),

        "sni": sni.strip(),

        "security": security,

        "type": "ws",

        "created_at":
            datetime.now(timezone.utc).isoformat(),

        "expires_at":
            expiration.isoformat(),

        "enabled": True
    }

    state["configs"].insert(
        0,
        config
    )

    save_state(state)

    return RedirectResponse(
        "/",
        status_code=303
    )


@app.post("/configs/{config_id}/toggle")
def toggle_config(
    request: Request,
    config_id: str
):

    require_auth(request)

    state = load_state()

    for config in state["configs"]:

        if config["id"] == config_id:

            config["enabled"] = not config["enabled"]

            save_state(state)

            break

    return RedirectResponse(
        "/",
        status_code=303
    )


@app.post("/configs/{config_id}/delete")
def delete_config(
    request: Request,
    config_id: str
):

    require_auth(request)

    state = load_state()

    state["configs"] = [
        config
        for config in state["configs"]
        if config["id"] != config_id
    ]

    save_state(state)

    return RedirectResponse(
        "/",
        status_code=303
    )


@app.get("/config/{config_id}")
def get_config(
    request: Request,
    config_id: str
):

    require_auth(request)

    state = load_state()

    for config in state["configs"]:

        if config["id"] == config_id:

            return Response(
                create_vless_link(config),
                media_type="text/plain"
            )

    raise HTTPException(
        status_code=404,
        detail="Config not found"
    )


@app.get("/sub/{config_id}")
def subscription(config_id: str):

    state = load_state()

    for config in state["configs"]:

        if (
            config["id"] == config_id
            and config.get("enabled")
        ):

            return Response(
                create_vless_link(config) + "\n",
                media_type="text/plain"
            )

    raise HTTPException(
        status_code=404,
        detail="Config not found"
    )


@app.get("/qr/{config_id}")
def qr_code(
    request: Request,
    config_id: str
):

    require_auth(request)

    state = load_state()

    for config in state["configs"]:

        if config["id"] == config_id:

            image = qrcode.make(
                create_vless_link(config)
            )

            buffer = BytesIO()

            image.save(
                buffer,
                format="PNG"
            )

            return Response(
                buffer.getvalue(),
                media_type="image/png"
            )

    raise HTTPException(
        status_code=404,
        detail="Config not found"
    )


@app.get("/health")
def health():

    return {
        "status": "ok"
    }