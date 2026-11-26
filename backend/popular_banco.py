import hashlib
import json
import secrets
from pathlib import Path
import psycopg

# Senha do banco PostgreSQL
SENHA_POSTGRES = "coinf123"
DSN = f"postgresql://postgres:{SENHA_POSTGRES}@localhost:5432/coinf_db"

# Senha inicial do usuário da Coordenação para entrar na aplicação
SENHA_ADMIN_APP = "coinf2026"
EMAIL_ADMIN_APP = "coinf@educacao.ba.gov.br"

PASTA_PROJETO = Path(__file__).resolve().parent.parent
ARQUIVO_ESCOLAS = PASTA_PROJETO / "frontend" / "escolas.json"


def gerar_hash_senha(senha: str) -> tuple[str, str]:
    salt = secrets.token_hex(16)
    dk = hashlib.pbkdf2_hmac("sha256", senha.encode("utf-8"), salt.encode("utf-8"), 120_000)
    return dk.hex(), salt


def limpar_texto(val, padrao=""):
    if val is None:
        return padrao
    texto = str(val).strip()
    return texto if texto else padrao


def extrair_territorio(nte_str: str) -> str:
    if " - " in nte_str:
        return nte_str.split(" - ", 1)[1].strip()
    return "Não informado"


def carregar_dados():
    with psycopg.connect(DSN) as conn:
        with conn.cursor() as cur:
            # 1. Garante ou atualiza o usuário inicial da Coordenação com a senha coinf2026
            senha_hash, salt = gerar_hash_senha(SENHA_ADMIN_APP)
            cur.execute("""
                INSERT INTO usuarios (nome, email, senha_hash, salt, perfil, cargo, ativo)
                VALUES (%s, %s, %s, %s, 'coordenacao', 'Coordenação COINF', TRUE)
                ON CONFLICT (email) DO UPDATE SET
                    senha_hash = EXCLUDED.senha_hash,
                    salt = EXCLUDED.salt,
                    perfil = 'coordenacao',
                    ativo = TRUE
            """, ("Coordenação COINF", EMAIL_ADMIN_APP, senha_hash, salt))

            # 2. Lê o formato tabular (cols / rows) do escolas.json
            dados_raw = json.loads(ARQUIVO_ESCOLAS.read_text(encoding="utf-8"))
            cols = dados_raw["cols"]
            rows = dados_raw["rows"]

            cache_municipios = {}
            qtd_esc = 0

            for row in rows:
                item = dict(zip(cols, row))

                mun_nome = limpar_texto(item.get("municipio"), "Não informado")
                nte = limpar_texto(item.get("nte"), "NTE 00")
                cod_ibge = limpar_texto(item.get("cod_ibge")) or None
                territorio = extrair_territorio(nte)

                chave_mun = (mun_nome, nte)
                if chave_mun not in cache_municipios:
                    cur.execute("""
                        INSERT INTO municipios (nte, nome, territorio, cod_ibge)
                        VALUES (%s, %s, %s, %s)
                        ON CONFLICT (nome, nte) DO UPDATE SET
                            territorio = EXCLUDED.territorio,
                            cod_ibge = COALESCE(EXCLUDED.cod_ibge, municipios.cod_ibge)
                        RETURNING id
                    """, (nte, mun_nome, territorio, cod_ibge))
                    cache_municipios[chave_mun] = cur.fetchone()[0]

                id_municipio = cache_municipios[chave_mun]

                esc_nome = limpar_texto(item.get("escola"))
                if not esc_nome:
                    continue

                cod_sec = limpar_texto(item.get("codigo_sec")) or None
                tipo = limpar_texto(item.get("tipo")) or ("Anexo" if item.get("anexo") == 1 else "Sede")
                anexo = int(item.get("anexo") or 0)
                endereco = limpar_texto(item.get("endereco")) or None
                lat = float(item["lat"]) if item.get("lat") not in (None, "") else None
                lon = float(item["lon"]) if item.get("lon") not in (None, "") else None
                porte = limpar_texto(item.get("porte")) or None

                if cod_sec:
                    cur.execute("""
                        INSERT INTO unidades_escolares (
                            id_municipio, nome, cod_sec, tipo, anexo, endereco, lat, lon, porte
                        )
                        VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s)
                        ON CONFLICT (cod_sec) DO UPDATE SET
                            id_municipio = EXCLUDED.id_municipio,
                            nome = EXCLUDED.nome,
                            tipo = EXCLUDED.tipo,
                            anexo = EXCLUDED.anexo,
                            endereco = EXCLUDED.endereco,
                            lat = EXCLUDED.lat,
                            lon = EXCLUDED.lon,
                            porte = EXCLUDED.porte
                    """, (id_municipio, esc_nome, cod_sec, tipo, anexo, endereco, lat, lon, porte))
                else:
                    cur.execute("""
                        INSERT INTO unidades_escolares (
                            id_municipio, nome, tipo, anexo, endereco, lat, lon, porte
                        )
                        VALUES (%s, %s, %s, %s, %s, %s, %s, %s)
                    """, (id_municipio, esc_nome, tipo, anexo, endereco, lat, lon, porte))

                qtd_esc += 1

        conn.commit()

    print(f"✅ Carga concluída! Usuário {EMAIL_ADMIN_APP} (senha: {SENHA_ADMIN_APP}) pronto.")
    print(f"✅ {len(cache_municipios)} municípios e {qtd_esc} unidades escolares sincronizados no PostgreSQL.")


if __name__ == "__main__":
    carregar_dados()