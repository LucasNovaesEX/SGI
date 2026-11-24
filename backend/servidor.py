import asyncio
import hashlib
import hmac
import json
import secrets
import sqlite3
import uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

from fastapi import FastAPI, File, HTTPException, Request, Response, UploadFile
from fastapi.responses import FileResponse, RedirectResponse, StreamingResponse
from fastapi.staticfiles import StaticFiles

PASTA_PROJETO = Path(__file__).resolve().parent.parent
PASTA_FRONTEND = PASTA_PROJETO / "frontend"
PASTA_FOTOS = PASTA_PROJETO / "storage" / "fotos"
CAMINHO_BANCO = PASTA_PROJETO / "dados_coinf.db"

PASTA_FOTOS.mkdir(parents=True, exist_ok=True)

app = FastAPI(title="Força-Tarefa Rede de Escolas - COINF")
telas_conectadas: List[asyncio.Queue] = []

COOKIE_SESSAO = "coinf_session"
SENHA_PADRAO_INICIAL = "coinf2026"


def agora_utc() -> datetime:
    return datetime.now(timezone.utc)


def agora_iso() -> str:
    return agora_utc().isoformat()


def gerar_hash_senha(senha: str, salt: Optional[str] = None) -> tuple[str, str]:
    if not salt:
        salt = secrets.token_hex(16)
    dk = hashlib.pbkdf2_hmac(
        "sha256", senha.encode("utf-8"), salt.encode("utf-8"), 120_000
    )
    return dk.hex(), salt


def verificar_senha(senha: str, senha_hash: Optional[str], salt: Optional[str]) -> bool:
    if not senha_hash or not salt:
        return False
    calculado, _ = gerar_hash_senha(senha, salt)
    return hmac.compare_digest(calculado, senha_hash)


def abrir_conexao() -> sqlite3.Connection:
    conn = sqlite3.connect(CAMINHO_BANCO)
    conn.row_factory = sqlite3.Row
    return conn


def iniciar_banco():
    conn = abrir_conexao()
    cur = conn.cursor()

    cur.execute("""
        CREATE TABLE IF NOT EXISTS usuarios (
            id TEXT PRIMARY KEY,
            nome TEXT NOT NULL,
            email TEXT UNIQUE NOT NULL,
            is_owner INTEGER NOT NULL DEFAULT 0,
            pode_escrever INTEGER NOT NULL DEFAULT 1,
            senha_hash TEXT,
            salt TEXT
        )
    """)

    # Garante compatibilidade com o banco já criado no passo anterior
    colunas = [r["name"] for r in cur.execute("PRAGMA table_info(usuarios)").fetchall()]
    if "senha_hash" not in colunas:
        cur.execute("ALTER TABLE usuarios ADD COLUMN senha_hash TEXT")
    if "salt" not in colunas:
        cur.execute("ALTER TABLE usuarios ADD COLUMN salt TEXT")

    cur.execute("""
        CREATE TABLE IF NOT EXISTS sessoes (
            token TEXT PRIMARY KEY,
            user_id TEXT NOT NULL,
            criado_em TEXT NOT NULL,
            expira_em TEXT NOT NULL
        )
    """)

    cur.execute("""
        CREATE TABLE IF NOT EXISTS registros (
            colecao TEXT NOT NULL,
            doc_id TEXT NOT NULL,
            dados TEXT NOT NULL,
            atualizado_em TEXT NOT NULL,
            PRIMARY KEY (colecao, doc_id)
        )
    """)

    cur.execute("""
        CREATE TABLE IF NOT EXISTS historico (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            em TEXT NOT NULL,
            por TEXT,
            acao TEXT NOT NULL,
            alvo TEXT,
            detalhe TEXT
        )
    """)

    cur.execute("""
        CREATE TABLE IF NOT EXISTS arquivos (
            id TEXT PRIMARY KEY,
            nome_arquivo TEXT NOT NULL,
            mime_type TEXT NOT NULL,
            size_bytes INTEGER NOT NULL,
            criado_em TEXT NOT NULL
        )
    """)

    # Cria ou atualiza a senha do administrador padrão
    senha_hash, salt = gerar_hash_senha(SENHA_PADRAO_INICIAL)
    cur.execute("""
        INSERT OR IGNORE INTO usuarios (id, nome, email, is_owner, pode_escrever, senha_hash, salt)
        VALUES ('coord_coinf', 'Coordenação COINF', 'coinf@educacao.ba.gov.br', 1, 1, ?, ?)
    """, (senha_hash, salt))

    cur.execute("""
        UPDATE usuarios
        SET senha_hash = ?, salt = ?
        WHERE id = 'coord_coinf' AND (senha_hash IS NULL OR senha_hash = '')
    """, (senha_hash, salt))

    conn.commit()
    conn.close()


iniciar_banco()


def obter_usuario_sessao(request: Request) -> Optional[dict]:
    token = request.cookies.get(COOKIE_SESSAO)
    if not token:
        return None
    conn = abrir_conexao()
    row = conn.execute("""
        SELECT u.id, u.nome, u.email, u.is_owner, u.pode_escrever, s.expira_em
        FROM sessoes s
        JOIN usuarios u ON u.id = s.user_id
        WHERE s.token = ?
    """, (token,)).fetchone()
    conn.close()
    if not row:
        return None
    if row["expira_em"] <= agora_iso():
        return None
    return dict(row)


def exigir_usuario(request: Request) -> dict:
    usuario = obter_usuario_sessao(request)
    if not usuario:
        raise HTTPException(status_code=401, detail="Faça login para continuar.")
    return usuario


def exigir_coordenador(request: Request) -> dict:
    usuario = exigir_usuario(request)
    if not usuario["is_owner"]:
        raise HTTPException(status_code=403, detail="Acesso restrito à Coordenação.")
    return usuario


async def avisar_telas(colecao: str):
    mensagem = json.dumps({"colecao": colecao})
    for fila in list(telas_conectadas):
        await fila.put(mensagem)


# ==============================================================================
# ROTAS DE LOGIN, LOGOUT E GERENCIAMENTO DE USUÁRIOS
# ==============================================================================

@app.post("/api/login")
async def login(request: Request, response: Response):
    corpo = await request.json()
    email = (corpo.get("email") or "").strip().lower()
    senha = corpo.get("senha") or ""

    conn = abrir_conexao()
    user = conn.execute(
        "SELECT * FROM usuarios WHERE lower(email) = ?", (email,)
    ).fetchone()

    if not user or not verificar_senha(senha, user["senha_hash"], user["salt"]):
        conn.close()
        raise HTTPException(status_code=401, detail="E-mail ou senha incorretos.")

    token = secrets.token_urlsafe(32)
    expira = (agora_utc() + timedelta(days=30)).isoformat()
    conn.execute(
        "INSERT INTO sessoes (token, user_id, criado_em, expira_em) VALUES (?, ?, ?, ?)",
        (token, user["id"], agora_iso(), expira),
    )
    conn.commit()
    conn.close()

    response.set_cookie(
        key=COOKIE_SESSAO,
        value=token,
        httponly=True,
        samesite="lax",
        max_age=30 * 24 * 3600,
        path="/",
    )
    return {"ok": True}


@app.post("/api/logout")
def logout(request: Request, response: Response):
    token = request.cookies.get(COOKIE_SESSAO)
    if token:
        conn = abrir_conexao()
        conn.execute("DELETE FROM sessoes WHERE token = ?", (token,))
        conn.commit()
        conn.close()
    response.delete_cookie(key=COOKIE_SESSAO, path="/")
    return {"ok": True}


@app.get("/api/me")
def usuario_atual(request: Request):
    u = exigir_usuario(request)
    return {
        "uid": u["id"],
        "nome": u["nome"],
        "email": u["email"],
        "isOwner": bool(u["is_owner"]),
        "canWrite": bool(u["pode_escrever"]),
    }


@app.post("/api/users/profiles")
async def perfis_usuarios(request: Request):
    exigir_usuario(request)
    corpo = await request.json()
    ids = corpo.get("ids", [])
    if not ids:
        return {}
    conn = abrir_conexao()
    marcadores = ",".join("?" for _ in ids)
    rows = conn.execute(
        f"SELECT id, nome, email FROM usuarios WHERE id IN ({marcadores})", ids
    ).fetchall()
    conn.close()
    return {r["id"]: {"name": r["nome"], "email": r["email"]} for r in rows}


@app.get("/api/admin/usuarios")
def listar_usuarios_admin(request: Request):
    exigir_coordenador(request)
    conn = abrir_conexao()
    rows = conn.execute(
        "SELECT id, nome, email, is_owner, pode_escrever FROM usuarios ORDER BY is_owner DESC, nome ASC"
    ).fetchall()
    conn.close()
    return {"usuarios": [dict(r) for r in rows]}


@app.post("/api/admin/usuarios")
async def criar_usuario_admin(request: Request):
    exigir_coordenador(request)
    corpo = await request.json()
    nome = (corpo.get("nome") or "").strip()
    email = (corpo.get("email") or "").strip().lower()
    senha = corpo.get("senha") or ""
    perfil = corpo.get("perfil") or "fiscal"

    if not nome or not email or len(senha) < 4:
        raise HTTPException(status_code=400, detail="Preencha nome, e-mail e senha (mínimo 4 caracteres).")

    is_owner = 1 if perfil == "coordenador" else 0
    pode_escrever = 0 if perfil == "leitura" else 1
    senha_hash, salt = gerar_hash_senha(senha)
    novo_id = f"usr_{uuid.uuid4().hex[:10]}"

    conn = abrir_conexao()
    try:
        conn.execute(
            """
            INSERT INTO usuarios (id, nome, email, is_owner, pode_escrever, senha_hash, salt)
            VALUES (?, ?, ?, ?, ?, ?, ?)
            """,
            (novo_id, nome, email, is_owner, pode_escrever, senha_hash, salt),
        )
        conn.commit()
    except sqlite3.IntegrityError:
        conn.close()
        raise HTTPException(status_code=400, detail="Já existe um usuário cadastrado com esse e-mail.")
    conn.close()
    return {"ok": True, "id": novo_id}


@app.patch("/api/admin/usuarios/{user_id}")
async def atualizar_usuario_admin(user_id: str, request: Request):
    exigir_coordenador(request)
    corpo = await request.json()
    senha = corpo.get("senha")
    if senha:
        if len(senha) < 4:
            raise HTTPException(status_code=400, detail="A senha deve ter pelo menos 4 caracteres.")
        senha_hash, salt = gerar_hash_senha(senha)
        conn = abrir_conexao()
        conn.execute(
            "UPDATE usuarios SET senha_hash = ?, salt = ? WHERE id = ?",
            (senha_hash, salt, user_id),
        )
        conn.commit()
        conn.close()
    return {"ok": True}


@app.delete("/api/admin/usuarios/{user_id}")
def apagar_usuario_admin(user_id: str, request: Request):
    atual = exigir_coordenador(request)
    if atual["id"] == user_id:
        raise HTTPException(status_code=400, detail="Você não pode excluir o seu próprio usuário.")
    conn = abrir_conexao()
    conn.execute("DELETE FROM sessoes WHERE user_id = ?", (user_id,))
    conn.execute("DELETE FROM usuarios WHERE id = ?", (user_id,))
    conn.commit()
    conn.close()
    return {"ok": True}


# ==============================================================================
# CANAL AO VIVO E ROTAS DO BANCO DE DADOS (PROTEGIDAS POR LOGIN)
# ==============================================================================

@app.get("/api/eventos")
async def canal_ao_vivo(request: Request):
    exigir_usuario(request)
    fila: asyncio.Queue = asyncio.Queue()
    telas_conectadas.append(fila)

    async def gerador():
        try:
            yield "data: {\"conectado\": true}\n\n"
            while True:
                if await request.is_disconnected():
                    break
                try:
                    evento = await asyncio.wait_for(fila.get(), timeout=20.0)
                    yield f"data: {evento}\n\n"
                except asyncio.TimeoutError:
                    yield ": ping\n\n"
        finally:
            if fila in telas_conectadas:
                telas_conectadas.remove(fila)

    return StreamingResponse(gerador(), media_type="text/event-stream")


@app.get("/api/db/historico")
def listar_historico(request: Request, limit: int = 300):
    exigir_usuario(request)
    conn = abrir_conexao()
    rows = conn.execute(
        "SELECT em, por, acao, alvo, detalhe FROM historico ORDER BY em DESC LIMIT ?",
        (limit,),
    ).fetchall()
    conn.close()
    return {"docs": [dict(r) for r in rows]}


@app.post("/api/db/historico")
async def registrar_historico(request: Request):
    u = exigir_usuario(request)
    d = await request.json()
    conn = abrir_conexao()
    conn.execute(
        "INSERT INTO historico (em, por, acao, alvo, detalhe) VALUES (?, ?, ?, ?, ?)",
        (
            d.get("em") or agora_iso(),
            d.get("por") or u["id"],
            d.get("acao", ""),
            d.get("alvo", ""),
            d.get("detalhe", ""),
        ),
    )
    conn.commit()
    conn.close()
    return {"ok": True}


@app.get("/api/db/{colecao}")
def listar_colecao(colecao: str, request: Request):
    exigir_usuario(request)
    conn = abrir_conexao()
    rows = conn.execute(
        "SELECT doc_id, dados FROM registros WHERE colecao = ?", (colecao,)
    ).fetchall()
    conn.close()
    return {
        "docs": [{"id": r["doc_id"], "data": json.loads(r["dados"])} for r in rows]
    }


@app.get("/api/db/{colecao}/{doc_id}")
def ler_documento(colecao: str, doc_id: str, request: Request):
    exigir_usuario(request)
    conn = abrir_conexao()
    row = conn.execute(
        "SELECT dados FROM registros WHERE colecao = ? AND doc_id = ?",
        (colecao, doc_id),
    ).fetchone()
    conn.close()
    if not row:
        return {"exists": False, "id": doc_id, "data": None}
    return {"exists": True, "id": doc_id, "data": json.loads(row["dados"])}


@app.put("/api/db/{colecao}/{doc_id}")
async def salvar_documento(colecao: str, doc_id: str, request: Request):
    u = exigir_usuario(request)
    if not u["pode_escrever"]:
        raise HTTPException(status_code=403, detail="Usuário em modo somente leitura.")
    dados = await request.json()
    conn = abrir_conexao()
    conn.execute(
        """
        INSERT INTO registros (colecao, doc_id, dados, atualizado_em)
        VALUES (?, ?, ?, ?)
        ON CONFLICT(colecao, doc_id) DO UPDATE SET
            dados = excluded.dados,
            atualizado_em = excluded.atualizado_em
        """,
        (colecao, doc_id, json.dumps(dados, ensure_ascii=False), agora_iso()),
    )
    conn.commit()
    conn.close()
    await avisar_telas(colecao)
    return {"ok": True}


@app.patch("/api/db/{colecao}/{doc_id}")
async def atualizar_documento(colecao: str, doc_id: str, request: Request):
    u = exigir_usuario(request)
    if not u["pode_escrever"]:
        raise HTTPException(status_code=403, detail="Usuário em modo somente leitura.")
    novos_campos: Dict[str, Any] = await request.json()
    conn = abrir_conexao()
    row = conn.execute(
        "SELECT dados FROM registros WHERE colecao = ? AND doc_id = ?",
        (colecao, doc_id),
    ).fetchone()
    atual = json.loads(row["dados"]) if row else {}
    atual.update(novos_campos)
    conn.execute(
        """
        INSERT INTO registros (colecao, doc_id, dados, atualizado_em)
        VALUES (?, ?, ?, ?)
        ON CONFLICT(colecao, doc_id) DO UPDATE SET
            dados = excluded.dados,
            atualizado_em = excluded.atualizado_em
        """,
        (colecao, doc_id, json.dumps(atual, ensure_ascii=False), agora_iso()),
    )
    conn.commit()
    conn.close()
    await avisar_telas(colecao)
    return {"ok": True}


@app.delete("/api/db/{colecao}/{doc_id}")
async def apagar_documento(colecao: str, doc_id: str, request: Request):
    u = exigir_usuario(request)
    if not u["pode_escrever"]:
        raise HTTPException(status_code=403, detail="Usuário em modo somente leitura.")
    conn = abrir_conexao()
    conn.execute(
        "DELETE FROM registros WHERE colecao = ? AND doc_id = ?", (colecao, doc_id)
    )
    conn.commit()
    conn.close()
    await avisar_telas(colecao)
    return {"ok": True}


# ==============================================================================
# ROTAS DE FOTOS (PROTEGIDAS POR LOGIN)
# ==============================================================================

@app.post("/api/assets")
async def enviar_foto(request: Request, file: UploadFile = File(...)):
    u = exigir_usuario(request)
    if not u["pode_escrever"]:
        raise HTTPException(status_code=403, detail="Usuário em modo somente leitura.")
    conteudo = await file.read()
    asset_id = uuid.uuid4().hex
    nome_arquivo = f"{asset_id}.jpg"
    caminho = PASTA_FOTOS / nome_arquivo
    caminho.write_bytes(conteudo)

    conn = abrir_conexao()
    conn.execute(
        "INSERT INTO arquivos (id, nome_arquivo, mime_type, size_bytes, criado_em) VALUES (?, ?, ?, ?, ?)",
        (asset_id, nome_arquivo, file.content_type or "image/jpeg", len(conteudo), agora_iso()),
    )
    conn.commit()
    conn.close()
    return {"id": asset_id, "sizeBytes": len(conteudo)}


@app.delete("/api/assets/{asset_id}")
def apagar_foto(asset_id: str, request: Request):
    u = exigir_usuario(request)
    if not u["pode_escrever"]:
        raise HTTPException(status_code=403, detail="Usuário em modo somente leitura.")
    conn = abrir_conexao()
    row = conn.execute(
        "SELECT nome_arquivo FROM arquivos WHERE id = ?", (asset_id,)
    ).fetchone()
    if row:
        caminho = PASTA_FOTOS / row["nome_arquivo"]
        if caminho.exists():
            caminho.unlink()
        conn.execute("DELETE FROM arquivos WHERE id = ?", (asset_id,))
        conn.commit()
    conn.close()
    return {"ok": True}


@app.get("/api/assets/usage")
def uso_armazenamento(request: Request):
    exigir_usuario(request)
    conn = abrir_conexao()
    row = conn.execute(
        "SELECT COUNT(*) AS qtd, COALESCE(SUM(size_bytes), 0) AS bytes FROM arquivos"
    ).fetchone()
    conn.close()
    return {
        "usage": {
            "bytes": row["bytes"],
            "maxBytes": 1073741824,
            "files": row["qtd"],
            "maxFiles": 10000,
        }
    }


@app.get("/_blob/{asset_id}")
def abrir_foto(asset_id: str, request: Request):
    exigir_usuario(request)
    conn = abrir_conexao()
    row = conn.execute(
        "SELECT nome_arquivo, mime_type FROM arquivos WHERE id = ?", (asset_id,)
    ).fetchone()
    conn.close()
    nome = row["nome_arquivo"] if row else f"{asset_id}.jpg"
    mime = row["mime_type"] if row else "image/jpeg"
    caminho = PASTA_FOTOS / nome
    if not caminho.exists():
        raise HTTPException(status_code=404, detail="Foto não encontrada")
    return FileResponse(caminho, media_type=mime)


# ==============================================================================
# ENTREGA DAS PÁGINAS (CONTROLADA PELO LOGIN)
# ==============================================================================

@app.get("/")
def abrir_sistema(request: Request):
    u = obter_usuario_sessao(request)
    if not u:
        return FileResponse(
            PASTA_FRONTEND / "login.html",
            headers={"Cache-Control": "no-store"},
        )
    return FileResponse(
        PASTA_FRONTEND / "index.html",
        headers={"Cache-Control": "no-store"},
    )


@app.get("/usuarios.html")
def abrir_gerenciador_usuarios(request: Request):
    u = obter_usuario_sessao(request)
    if not u or not u["is_owner"]:
        return RedirectResponse(url="/", status_code=302)
    return FileResponse(
        PASTA_FRONTEND / "usuarios.html",
        headers={"Cache-Control": "no-store"},
    )


app.mount("/", StaticFiles(directory=PASTA_FRONTEND), name="frontend")