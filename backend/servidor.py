import asyncio
import hashlib
import json
import os
import secrets
import uuid
from contextlib import asynccontextmanager
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Optional

import psycopg
from psycopg.rows import dict_row
from fastapi import Cookie, FastAPI, File, HTTPException, Request, Response, UploadFile
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, StreamingResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel

# ==============================================================================
# CONFIGURAÇÕES DO BANCO E DIRETÓRIOS
# ==============================================================================
SENHA_POSTGRES = os.getenv("POSTGRES_PASSWORD", "coinf123")
DSN = os.getenv(
    "DATABASE_URL",
    f"postgresql://postgres:{SENHA_POSTGRES}@localhost:5432/coinf_db",
)

PASTA_PROJETO = Path(__file__).resolve().parent.parent
PASTA_FRONTEND = PASTA_PROJETO / "frontend"
PASTA_STORAGE = PASTA_PROJETO / "storage"
PASTA_FOTOS = PASTA_STORAGE / "fotos"
PASTA_FOTOS.mkdir(parents=True, exist_ok=True)

SESSOES: dict[str, dict] = {}
FILAS_SSE: list[asyncio.Queue] = []


def get_conn():
    return psycopg.connect(DSN, row_factory=dict_row)


def gerar_hash_senha(senha: str) -> tuple[str, str]:
    salt = secrets.token_hex(16)
    dk = hashlib.pbkdf2_hmac("sha256", senha.encode("utf-8"), salt.encode("utf-8"), 120_000)
    return dk.hex(), salt


def verificar_senha(senha: str, senha_hash: str, salt: str) -> bool:
    dk = hashlib.pbkdf2_hmac("sha256", senha.encode("utf-8"), salt.encode("utf-8"), 120_000)
    return secrets.compare_digest(dk.hex(), senha_hash)


def registrar_historico(cur, id_usuario: Optional[int], acao: str, alvo: str = "", detalhe: str = ""):
    cur.execute(
        """
        INSERT INTO historico (id_usuario, acao, alvo, detalhe)
        VALUES (%s, %s, %s, %s)
        """,
        (id_usuario, acao, alvo, detalhe),
    )


# ==============================================================================
# ESPELHAMENTO EXATO PARA AS TABELAS RELACIONAIS DO POSTGRESQL
# ==============================================================================
MAPA_SISTEMAS_CHAVES = {
    "estrutura": "Estrutura",
    "cobertura": "Cobertura",
    "eletrica": "Instalações Elétricas",
    "hidro": "Instalações Hidrossanitárias",
    "esquadrias": "Esquadrias",
    "pisos": "Pisos e Revestimentos",
    "acess": "Acessibilidade",
    "incendio": "Prevenção de Incêndio",
}


def localizar_escola(cur, cod_sec: str) -> Optional[int]:
    if not cod_sec:
        return None
    cur.execute("SELECT id FROM unidades_escolares WHERE cod_sec = %s LIMIT 1", (str(cod_sec).strip(),))
    row = cur.fetchone()
    return row["id"] if row else None


def garantir_vistoria_escola(cur, id_unid_esc: int, id_usuario: int, data_vistoria: str) -> int:
    cur.execute(
        """
        SELECT id FROM vistorias
        WHERE id_unid_esc = %s
        ORDER BY id DESC LIMIT 1
        """,
        (id_unid_esc,),
    )
    existente = cur.fetchone()
    if existente:
        return existente["id"]

    cur.execute(
        """
        INSERT INTO vistorias (id_unid_esc, id_usuario, data_vistoria)
        VALUES (%s, %s, %s)
        RETURNING id
        """,
        (id_unid_esc, id_usuario, data_vistoria),
    )
    return cur.fetchone()["id"]


def espelhar_documento_relacional(cur, colecao: str, doc_id: str, item: dict, id_usuario: int):
    if not isinstance(item, dict):
        return

    # 1. Coleção DIAGNOSTICOS (doc_id = cod_sec da escola)
    if colecao == "diagnosticos":
        id_unid_esc = localizar_escola(cur, doc_id)
        if not id_unid_esc:
            return

        data_vist = item.get("data") or datetime.now().strftime("%Y-%m-%d")
        id_vistoria = garantir_vistoria_escola(cur, id_unid_esc, id_usuario, data_vist)

        patologias = str(item.get("obs") or "")
        if item.get("risco") and item.get("riscoDesc"):
            patologias = f"[RISCO IMINENTE: {item['riscoDesc']}] {patologias}".strip()

        recomendacoes = str(item.get("rec") or "")
        nota_final = float(item.get("nota") or item.get("total") or 0)
        prioridade = str(item.get("prioridade") or "")
        fiscal = str(item.get("fiscal") or "")
        empresa = str(item.get("empresa") or "")
        funcionamento = str(item.get("funcionamento") or "")

        cur.execute(
            """
            UPDATE vistorias
            SET id_usuario = %s,
                data_vistoria = %s,
                fiscal_responsavel = COALESCE(NULLIF(%s, ''), fiscal_responsavel),
                empresa_executora = COALESCE(NULLIF(%s, ''), empresa_executora),
                em_funcionamento = COALESCE(NULLIF(%s, ''), em_funcionamento),
                patologias_encontradas = %s,
                recomendacoes = %s,
                nota_final = %s,
                prioridade = %s,
                atualizado_em = NOW()
            WHERE id = %s
            """,
            (
                id_usuario,
                data_vist,
                fiscal,
                empresa,
                funcionamento,
                patologias,
                recomendacoes,
                nota_final,
                prioridade,
                id_vistoria,
            ),
        )

        gut = item.get("gut") or {}
        if isinstance(gut, dict):
            cur.execute("SELECT id, sistema FROM pesos_gut")
            pesos_db = {row["sistema"]: row["id"] for row in cur.fetchall()}

            for chave_sis, notas in gut.items():
                nome_oficial = MAPA_SISTEMAS_CHAVES.get(chave_sis.lower())
                if not nome_oficial or nome_oficial not in pesos_db or not isinstance(notas, dict):
                    continue

                g = int(notas.get("g") or 0)
                u = int(notas.get("u") or 0)
                t = int(notas.get("t") or 0)
                if 1 <= g <= 10 and 1 <= u <= 10 and 1 <= t <= 10:
                    cur.execute(
                        """
                        INSERT INTO vistorias_sistemas (
                            id_vistoria, id_peso_gut, gravidade, urgencia, tendencia
                        )
                        VALUES (%s, %s, %s, %s, %s)
                        ON CONFLICT (id_vistoria, id_peso_gut) DO UPDATE SET
                            gravidade = EXCLUDED.gravidade,
                            urgencia = EXCLUDED.urgencia,
                            tendencia = EXCLUDED.tendencia
                        """,
                        (id_vistoria, pesos_db[nome_oficial], g, u, t),
                    )

    # 2. Coleção VISITAS (doc_id = cod_sec da escola)
    elif colecao == "visitas":
        id_unid_esc = localizar_escola(cur, doc_id)
        if not id_unid_esc:
            return

        data_vist = item.get("fim") or item.get("inicio") or datetime.now().strftime("%Y-%m-%d")
        id_vistoria = garantir_vistoria_escola(cur, id_unid_esc, id_usuario, data_vist)
        fiscal = str(item.get("fiscal") or "")
        status = str(item.get("status") or "")

        cur.execute(
            """
            UPDATE vistorias
            SET fiscal_responsavel = COALESCE(NULLIF(%s, ''), fiscal_responsavel),
                status_visita = COALESCE(NULLIF(%s, ''), status_visita),
                atualizado_em = NOW()
            WHERE id = %s
            """,
            (fiscal, status, id_vistoria),
        )

    # 3. Coleção FOTOS (dados['cod'] = cod_sec, dados['asset'] = uuid do arquivo)
    elif colecao == "fotos":
        cod_sec = str(item.get("cod") or "").strip()
        asset_id = str(item.get("asset") or "").strip()
        if not cod_sec or not asset_id:
            return

        id_unid_esc = localizar_escola(cur, cod_sec)
        if not id_unid_esc:
            return

        id_vistoria = garantir_vistoria_escola(cur, id_unid_esc, id_usuario, datetime.now().strftime("%Y-%m-%d"))
        legenda = str(item.get("legenda") or "")
        tamanho_bytes = int(item.get("bytes") or 0)

        caminho_relativo = f"storage/fotos/{asset_id}.jpg"
        for candidato in PASTA_FOTOS.glob(f"{asset_id}.*"):
            caminho_relativo = f"storage/fotos/{candidato.name}"
            break

        try:
            cur.execute(
                """
                INSERT INTO fotos (id, id_vistoria, caminho_arquivo, legenda, tamanho_bytes)
                VALUES (%s::uuid, %s, %s, %s, %s)
                ON CONFLICT (id) DO UPDATE SET
                    id_vistoria = EXCLUDED.id_vistoria,
                    legenda = EXCLUDED.legenda
                """,
                (asset_id, id_vistoria, caminho_relativo, legenda, tamanho_bytes),
            )
        except Exception:
            pass


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Garante usuário admin, colunas extras em vistorias e sincroniza registros existentes."""
    try:
        with get_conn() as conn:
            with conn.cursor() as cur:
                # 1. Garante colunas complementares na tabela vistorias
                cur.execute("""
                    ALTER TABLE vistorias
                        ADD COLUMN IF NOT EXISTS fiscal_responsavel VARCHAR(150),
                        ADD COLUMN IF NOT EXISTS empresa_executora VARCHAR(150),
                        ADD COLUMN IF NOT EXISTS em_funcionamento VARCHAR(30),
                        ADD COLUMN IF NOT EXISTS status_visita VARCHAR(50);
                """)

                # 2. Garante usuário inicial da Coordenação
                cur.execute("SELECT id FROM usuarios WHERE LOWER(email) = 'coinf@educacao.ba.gov.br'")
                admin = cur.fetchone()
                if not admin:
                    senha_hash, salt = gerar_hash_senha("coinf2026")
                    cur.execute(
                        """
                        INSERT INTO usuarios (nome, email, senha_hash, salt, perfil, cargo, ativo)
                        VALUES (%s, %s, %s, %s, 'coordenacao', 'Coordenação COINF', TRUE)
                        RETURNING id
                        """,
                        ("Coordenação COINF", "coinf@educacao.ba.gov.br", senha_hash, salt),
                    )
                    admin_id = cur.fetchone()["id"]
                else:
                    admin_id = admin["id"]

                # 3. Sincroniza para as tabelas relacionais o que já estiver em registros_kv
                cur.execute(
                    """
                    SELECT colecao, doc_id, dados, COALESCE(atualizado_por, %s) AS uid
                    FROM registros_kv
                    WHERE colecao IN ('diagnosticos', 'visitas', 'fotos')
                    ORDER BY atualizado_em ASC
                    """,
                    (admin_id,),
                )
                for reg in cur.fetchall():
                    espelhar_documento_relacional(cur, reg["colecao"], reg["doc_id"], reg["dados"], reg["uid"])

            conn.commit()
    except Exception as exc:
        print(f"⚠️ Aviso na inicialização do PostgreSQL: {exc}")
    yield


app = FastAPI(title="Força-Tarefa Rede de Escolas - COINF (PostgreSQL)", lifespan=lifespan)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


async def notificar_sse(colecao: str):
    payload = json.dumps({"colecao": colecao})
    for fila in list(FILAS_SSE):
        try:
            fila.put_nowait(payload)
        except Exception:
            pass


def obter_usuario_sessao(session_token: Optional[str]) -> Optional[dict]:
    if not session_token:
        return None
    sessao = SESSOES.get(session_token)
    if not sessao:
        return None
    if sessao["expira_em"] < datetime.now(timezone.utc):
        SESSOES.pop(session_token, None)
        return None
    return sessao


def exigir_usuario(session_token: Optional[str], exigir_escrita: bool = False, exigir_admin: bool = False) -> dict:
    user = obter_usuario_sessao(session_token)
    if not user:
        raise HTTPException(status_code=401, detail="Não autenticado.")
    if exigir_admin and not user["isOwner"]:
        raise HTTPException(status_code=403, detail="Acesso restrito à Coordenação.")
    if exigir_escrita and not user["canWrite"]:
        raise HTTPException(status_code=403, detail="Perfil somente leitura.")
    return user


# ==============================================================================
# ROTAS DE AUTENTICAÇÃO (/api/login, /api/logout, /api/me)
# ==============================================================================
class LoginInput(BaseModel):
    email: str
    senha: str


@app.post("/api/login")
def login(body: LoginInput, response: Response):
    email_limpo = body.email.strip().lower()
    with get_conn() as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                SELECT id, nome, email, senha_hash, salt, perfil, cargo, ativo
                FROM usuarios
                WHERE LOWER(email) = %s
                """,
                (email_limpo,),
            )
            user = cur.fetchone()

            if not user or not user["ativo"] or not verificar_senha(body.senha, user["senha_hash"], user["salt"]):
                raise HTTPException(status_code=401, detail="E-mail ou senha inválidos.")

            token = secrets.token_urlsafe(32)
            is_owner = user["perfil"] == "coordenacao"
            can_write = user["perfil"] in ("coordenacao", "fiscal", "administrativo")

            sessao = {
                "id": user["id"],
                "uid": str(user["id"]),
                "nome": user["nome"],
                "email": user["email"],
                "perfil": user["perfil"],
                "cargo": user["cargo"] or "",
                "isOwner": is_owner,
                "canWrite": can_write,
                "expira_em": datetime.now(timezone.utc) + timedelta(hours=12),
            }
            SESSOES[token] = sessao
            registrar_historico(cur, user["id"], "LOGIN", user["email"], "Login efetuado no sistema")
        conn.commit()

    response.set_cookie(
        key="session_token",
        value=token,
        httponly=True,
        samesite="lax",
        path="/",
        max_age=12 * 3600,
    )
    return {"ok": True, "usuario": {k: v for k, v in sessao.items() if k != "expira_em"}}


@app.post("/api/logout")
def logout(response: Response, session_token: Optional[str] = Cookie(default=None)):
    if session_token:
        SESSOES.pop(session_token, None)
    response.delete_cookie("session_token", path="/")
    return {"ok": True}


@app.get("/api/me")
def me(session_token: Optional[str] = Cookie(default=None)):
    user = exigir_usuario(session_token)
    return {k: v for k, v in user.items() if k != "expira_em"}


@app.post("/api/users/profiles")
async def users_profiles(request: Request, session_token: Optional[str] = Cookie(default=None)):
    exigir_usuario(session_token)
    body = await request.json()
    ids = body.get("ids") or []
    perfis = {}
    with get_conn() as conn:
        with conn.cursor() as cur:
            cur.execute("SELECT id, nome, email, cargo, perfil FROM usuarios")
            for r in cur.fetchall():
                uid = str(r["id"])
                if not ids or uid in [str(x) for x in ids]:
                    perfis[uid] = {
                        "id": uid,
                        "name": r["nome"],
                        "nome": r["nome"],
                        "email": r["email"],
                        "cargo": r["cargo"] or "",
                        "perfil": r["perfil"],
                    }
    return perfis


# ==============================================================================
# ADMINISTRAÇÃO DE USUÁRIOS (/api/admin/usuarios)
# ==============================================================================
@app.get("/api/admin/usuarios")
def admin_listar_usuarios(session_token: Optional[str] = Cookie(default=None)):
    exigir_usuario(session_token, exigir_admin=True)
    with get_conn() as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                SELECT id, nome, email, perfil, cargo, telefone, contratante, ativo, criado_em
                FROM usuarios
                ORDER BY nome
                """
            )
            lista = cur.fetchall()
            for u in lista:
                u["papel"] = {
                    "coordenacao": "admin",
                    "fiscal": "editor",
                    "administrativo": "editor",
                    "leitura": "leitor",
                }.get(u["perfil"], "editor")
                if u.get("criado_em"):
                    u["criado_em"] = u["criado_em"].isoformat()
    return {"usuarios": lista}


@app.post("/api/admin/usuarios")
async def admin_criar_usuario(request: Request, session_token: Optional[str] = Cookie(default=None)):
    admin = exigir_usuario(session_token, exigir_admin=True)
    body = await request.json()
    nome = (body.get("nome") or "").strip()
    email = (body.get("email") or "").strip().lower()
    senha = body.get("senha") or ""
    papel = (body.get("papel") or body.get("perfil") or "fiscal").lower()
    cargo = body.get("cargo") or ""
    telefone = body.get("telefone") or ""

    if not nome or not email or not senha:
        raise HTTPException(status_code=400, detail="Nome, e-mail e senha são obrigatórios.")

    perfil_db = {
        "admin": "coordenacao",
        "coordenacao": "coordenacao",
        "editor": "fiscal",
        "fiscal": "fiscal",
        "administrativo": "administrativo",
        "leitor": "leitura",
        "leitura": "leitura",
    }.get(papel, "fiscal")

    senha_hash, salt = gerar_hash_senha(senha)

    with get_conn() as conn:
        with conn.cursor() as cur:
            try:
                cur.execute(
                    """
                    INSERT INTO usuarios (nome, email, senha_hash, salt, perfil, cargo, telefone)
                    VALUES (%s, %s, %s, %s, %s, %s, %s)
                    RETURNING id
                    """,
                    (nome, email, senha_hash, salt, perfil_db, cargo, telefone),
                )
                novo_id = cur.fetchone()["id"]
                registrar_historico(cur, admin["id"], "CRIAR_USUARIO", email, f"Perfil: {perfil_db}")
            except psycopg.errors.UniqueViolation:
                raise HTTPException(status_code=400, detail="E-mail já cadastrado.")
        conn.commit()

    return {"ok": True, "id": novo_id}


@app.put("/api/admin/usuarios/{user_id}")
@app.patch("/api/admin/usuarios/{user_id}")
async def admin_editar_usuario(user_id: int, request: Request, session_token: Optional[str] = Cookie(default=None)):
    admin = exigir_usuario(session_token, exigir_admin=True)
    body = await request.json()

    perfil_map = {
        "admin": "coordenacao",
        "coordenacao": "coordenacao",
        "editor": "fiscal",
        "fiscal": "fiscal",
        "administrativo": "administrativo",
        "leitor": "leitura",
        "leitura": "leitura",
    }

    with get_conn() as conn:
        with conn.cursor() as cur:
            cur.execute("SELECT id, email FROM usuarios WHERE id = %s", (user_id,))
            alvo = cur.fetchone()
            if not alvo:
                raise HTTPException(status_code=404, detail="Usuário não encontrado.")

            if "nome" in body and body["nome"]:
                cur.execute("UPDATE usuarios SET nome = %s WHERE id = %s", (body["nome"].strip(), user_id))
            if "papel" in body or "perfil" in body:
                p_raw = (body.get("papel") or body.get("perfil") or "fiscal").lower()
                cur.execute("UPDATE usuarios SET perfil = %s WHERE id = %s", (perfil_map.get(p_raw, "fiscal"), user_id))
            if "cargo" in body:
                cur.execute("UPDATE usuarios SET cargo = %s WHERE id = %s", (body["cargo"], user_id))
            if "telefone" in body:
                cur.execute("UPDATE usuarios SET telefone = %s WHERE id = %s", (body["telefone"], user_id))
            if "ativo" in body:
                cur.execute("UPDATE usuarios SET ativo = %s WHERE id = %s", (bool(body["ativo"]), user_id))
            if body.get("senha"):
                senha_hash, salt = gerar_hash_senha(body["senha"])
                cur.execute(
                    "UPDATE usuarios SET senha_hash = %s, salt = %s WHERE id = %s",
                    (senha_hash, salt, user_id),
                )

            registrar_historico(cur, admin["id"], "EDITAR_USUARIO", alvo["email"], "Cadastro atualizado")
        conn.commit()

    return {"ok": True}


@app.delete("/api/admin/usuarios/{user_id}")
def admin_excluir_usuario(user_id: int, session_token: Optional[str] = Cookie(default=None)):
    admin = exigir_usuario(session_token, exigir_admin=True)
    if admin["id"] == user_id:
        raise HTTPException(status_code=400, detail="Você não pode excluir seu próprio usuário.")
    with get_conn() as conn:
        with conn.cursor() as cur:
            cur.execute("DELETE FROM usuarios WHERE id = %s RETURNING email", (user_id,))
            removido = cur.fetchone()
            if removido:
                registrar_historico(cur, admin["id"], "EXCLUIR_USUARIO", removido["email"], "Usuário removido")
        conn.commit()
    return {"ok": True}


# ==============================================================================
# BANCO DE DADOS COMPATÍVEL COM CLAUDE-ADAPTER.JS (/api/db/...)
# ==============================================================================
@app.get("/api/db/{caminho:path}")
def db_get(caminho: str, limit: Optional[int] = None, session_token: Optional[str] = Cookie(default=None)):
    exigir_usuario(session_token)
    partes = [p for p in caminho.split("/") if p]

    if len(partes) == 1 and partes[0] == "historico":
        lim = limit or 100
        with get_conn() as conn:
            with conn.cursor() as cur:
                cur.execute(
                    """
                    SELECT h.id, h.em, h.acao, h.alvo, h.detalhe, COALESCE(u.nome, 'Sistema') AS usuario
                    FROM historico h
                    LEFT JOIN usuarios u ON u.id = h.id_usuario
                    ORDER BY h.id DESC
                    LIMIT %s
                    """,
                    (lim,),
                )
                rows = cur.fetchall()
                for r in rows:
                    if r.get("em"):
                        r["em"] = r["em"].isoformat()
        return {"docs": rows}

    with get_conn() as conn:
        with conn.cursor() as cur:
            if len(partes) == 1:
                colecao = partes[0]
                sql = "SELECT doc_id AS id, dados AS data FROM registros_kv WHERE colecao = %s ORDER BY atualizado_em DESC"
                params = [colecao]
                if limit:
                    sql += " LIMIT %s"
                    params.append(limit)
                cur.execute(sql, params)
                return {"docs": cur.fetchall()}

            colecao = "/".join(partes[:-1])
            doc_id = partes[-1]
            cur.execute(
                "SELECT dados FROM registros_kv WHERE colecao = %s AND doc_id = %s",
                (colecao, doc_id),
            )
            row = cur.fetchone()
            if not row:
                return {"exists": False, "data": None}
            return {"exists": True, "data": row["dados"]}


@app.post("/api/db/{caminho:path}")
async def db_post(caminho: str, request: Request, session_token: Optional[str] = Cookie(default=None)):
    user = exigir_usuario(session_token, exigir_escrita=True)
    dados = await request.json()
    colecao = caminho.strip("/")
    doc_id = str(dados.get("id") or uuid.uuid4())

    with get_conn() as conn:
        with conn.cursor() as cur:
            if colecao == "historico":
                registrar_historico(
                    cur,
                    user["id"],
                    str(dados.get("acao") or "REGISTRO"),
                    str(dados.get("alvo") or ""),
                    str(dados.get("detalhe") or ""),
                )
            else:
                cur.execute(
                    """
                    INSERT INTO registros_kv (colecao, doc_id, dados, atualizado_por, atualizado_em)
                    VALUES (%s, %s, %s::jsonb, %s, NOW())
                    ON CONFLICT (colecao, doc_id) DO UPDATE SET
                        dados = EXCLUDED.dados,
                        atualizado_por = EXCLUDED.atualizado_por,
                        atualizado_em = NOW()
                    """,
                    (colecao, doc_id, json.dumps(dados, ensure_ascii=False), user["id"]),
                )
                espelhar_documento_relacional(cur, colecao, doc_id, dados, user["id"])
        conn.commit()

    await notificar_sse(colecao)
    return {"ok": True, "id": doc_id}


@app.put("/api/db/{caminho:path}")
async def db_put(caminho: str, request: Request, session_token: Optional[str] = Cookie(default=None)):
    user = exigir_usuario(session_token, exigir_escrita=True)
    dados = await request.json()
    partes = [p for p in caminho.split("/") if p]
    colecao = "/".join(partes[:-1]) if len(partes) > 1 else partes[0]
    doc_id = partes[-1] if len(partes) > 1 else str(uuid.uuid4())

    with get_conn() as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                INSERT INTO registros_kv (colecao, doc_id, dados, atualizado_por, atualizado_em)
                VALUES (%s, %s, %s::jsonb, %s, NOW())
                ON CONFLICT (colecao, doc_id) DO UPDATE SET
                    dados = EXCLUDED.dados,
                    atualizado_por = EXCLUDED.atualizado_por,
                    atualizado_em = NOW()
                """,
                (colecao, doc_id, json.dumps(dados, ensure_ascii=False), user["id"]),
            )
            espelhar_documento_relacional(cur, colecao, doc_id, dados, user["id"])
        conn.commit()

    await notificar_sse(colecao)
    return {"ok": True, "id": doc_id}


@app.patch("/api/db/{caminho:path}")
async def db_patch(caminho: str, request: Request, session_token: Optional[str] = Cookie(default=None)):
    user = exigir_usuario(session_token, exigir_escrita=True)
    parcial = await request.json()
    partes = [p for p in caminho.split("/") if p]
    colecao = "/".join(partes[:-1]) if len(partes) > 1 else partes[0]
    doc_id = partes[-1]

    with get_conn() as conn:
        with conn.cursor() as cur:
            cur.execute(
                "SELECT dados FROM registros_kv WHERE colecao = %s AND doc_id = %s",
                (colecao, doc_id),
            )
            row = cur.fetchone()
            atual = row["dados"] if row and isinstance(row["dados"], dict) else {}
            atual.update(parcial)

            cur.execute(
                """
                INSERT INTO registros_kv (colecao, doc_id, dados, atualizado_por, atualizado_em)
                VALUES (%s, %s, %s::jsonb, %s, NOW())
                ON CONFLICT (colecao, doc_id) DO UPDATE SET
                    dados = EXCLUDED.dados,
                    atualizado_por = EXCLUDED.atualizado_por,
                    atualizado_em = NOW()
                """,
                (colecao, doc_id, json.dumps(atual, ensure_ascii=False), user["id"]),
            )
            espelhar_documento_relacional(cur, colecao, doc_id, atual, user["id"])
        conn.commit()

    await notificar_sse(colecao)
    return {"ok": True}


@app.delete("/api/db/{caminho:path}")
async def db_delete(caminho: str, session_token: Optional[str] = Cookie(default=None)):
    user = exigir_usuario(session_token, exigir_escrita=True)
    partes = [p for p in caminho.split("/") if p]
    colecao = "/".join(partes[:-1]) if len(partes) > 1 else partes[0]
    doc_id = partes[-1]

    with get_conn() as conn:
        with conn.cursor() as cur:
            cur.execute(
                "DELETE FROM registros_kv WHERE colecao = %s AND doc_id = %s",
                (colecao, doc_id),
            )
            registrar_historico(cur, user["id"], "EXCLUIR_DOC", f"{colecao}/{doc_id}", "Documento excluído")
        conn.commit()

    await notificar_sse(colecao)
    return {"ok": True}


# ==============================================================================
# EVENTOS EM TEMPO REAL (SSE - /api/eventos)
# ==============================================================================
@app.get("/api/eventos")
async def sse_eventos(request: Request, session_token: Optional[str] = Cookie(default=None)):
    exigir_usuario(session_token)
    fila: asyncio.Queue = asyncio.Queue()
    FILAS_SSE.append(fila)

    async def gerador():
        try:
            while True:
                if await request.is_disconnected():
                    break
                try:
                    msg = await asyncio.wait_for(fila.get(), timeout=20.0)
                    yield f"data: {msg}\n\n"
                except asyncio.TimeoutError:
                    yield ": keep-alive\n\n"
        finally:
            if fila in FILAS_SSE:
                FILAS_SSE.remove(fila)

    return StreamingResponse(gerador(), media_type="text/event-stream")


# ==============================================================================
# FOTOS / ASSETS (/api/assets e /_blob)
# ==============================================================================
@app.post("/api/assets")
async def upload_asset(file: UploadFile = File(...), session_token: Optional[str] = Cookie(default=None)):
    user = exigir_usuario(session_token, exigir_escrita=True)
    conteudo = await file.read()
    asset_id = str(uuid.uuid4())
    ext = Path(file.filename or "foto.jpg").suffix.lower() or ".jpg"
    if ext not in {".jpg", ".jpeg", ".png", ".webp"}:
        ext = ".jpg"

    nome_arquivo = f"{asset_id}{ext}"
    (PASTA_FOTOS / nome_arquivo).write_bytes(conteudo)

    with get_conn() as conn:
        with conn.cursor() as cur:
            registrar_historico(cur, user["id"], "UPLOAD_FOTO", nome_arquivo, f"{len(conteudo)} bytes")
        conn.commit()

    return {"id": asset_id, "url": f"/_blob/{asset_id}"}


@app.get("/api/assets/usage")
def assets_usage(session_token: Optional[str] = Cookie(default=None)):
    exigir_usuario(session_token)
    arquivos = [p for p in PASTA_FOTOS.glob("*") if p.is_file()]
    total_bytes = sum(p.stat().st_size for p in arquivos)
    return {
        "count": len(arquivos),
        "bytes": total_bytes,
        "items": [{"id": p.stem, "url": f"/_blob/{p.stem}", "bytes": p.stat().st_size} for p in arquivos],
    }


@app.get("/api/assets/{asset_id}")
@app.get("/_blob/{asset_id}")
def get_asset(asset_id: str):
    for candidato in PASTA_FOTOS.glob(f"{asset_id}.*"):
        return FileResponse(candidato)
    raise HTTPException(status_code=404, detail="Imagem não encontrada.")


@app.delete("/api/assets/{asset_id}")
def delete_asset(asset_id: str, session_token: Optional[str] = Cookie(default=None)):
    user = exigir_usuario(session_token, exigir_escrita=True)
    for candidato in PASTA_FOTOS.glob(f"{asset_id}.*"):
        candidato.unlink(missing_ok=True)
    with get_conn() as conn:
        with conn.cursor() as cur:
            try:
                cur.execute("DELETE FROM fotos WHERE id = %s::uuid", (asset_id,))
            except Exception:
                pass
            registrar_historico(cur, user["id"], "EXCLUIR_FOTO", asset_id, "Foto removida")
        conn.commit()
    return {"ok": True}


# ==============================================================================
# PROTEÇÃO DE PÁGINAS E ARQUIVOS ESTÁTICOS (SEM CACHE NA ROTA RAIZ)
# ==============================================================================
@app.get("/")
def raiz(session_token: Optional[str] = Cookie(default=None)):
    user = obter_usuario_sessao(session_token)
    arquivo = PASTA_FRONTEND / ("index.html" if user else "login.html")
    return FileResponse(
        arquivo,
        headers={
            "Cache-Control": "no-store, no-cache, must-revalidate, max-age=0",
            "Pragma": "no-cache",
            "Expires": "0",
        },
    )


@app.get("/usuarios.html")
def pagina_usuarios(session_token: Optional[str] = Cookie(default=None)):
    user = obter_usuario_sessao(session_token)
    if not user:
        return FileResponse(
            PASTA_FRONTEND / "login.html",
            headers={"Cache-Control": "no-store, no-cache, must-revalidate, max-age=0"},
        )
    if not user["isOwner"]:
        raise HTTPException(status_code=403, detail="Acesso restrito à Coordenação.")
    return FileResponse(
        PASTA_FRONTEND / "usuarios.html",
        headers={"Cache-Control": "no-store, no-cache, must-revalidate, max-age=0"},
    )


app.mount("/", StaticFiles(directory=str(PASTA_FRONTEND)), name="frontend")


if __name__ == "__main__":
    import uvicorn

    uvicorn.run("servidor:app", host="0.0.0.0", port=8000, reload=True)