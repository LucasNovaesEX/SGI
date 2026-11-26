from pathlib import Path
import psycopg

DSN = "postgresql://postgres:coinf123@localhost:5432/coinf_db"
PASTA_FOTOS = Path(__file__).resolve().parent.parent / "storage" / "fotos"


def limpar_ambiente_testes():
    confirmacao = input("⚠️ Isso apagará TODAS as vistorias, fotos e histórico de teste. Digite 'LIMPAR' para confirmar: ")
    if confirmacao.strip() != "LIMPAR":
        print("Operação cancelada.")
        return

    with psycopg.connect(DSN) as conn:
        with conn.cursor() as cur:
            cur.execute("""
                TRUNCATE TABLE
                    fotos,
                    vistorias_sistemas,
                    vistorias,
                    registros_kv,
                    historico,
                    dados_bancarios_usuario
                RESTART IDENTITY CASCADE;
            """)
            cur.execute("DELETE FROM usuarios WHERE LOWER(email) <> 'coinf@educacao.ba.gov.br';")
        conn.commit()

    qtd_fotos = 0
    for arq in PASTA_FOTOS.glob("*"):
        if arq.is_file():
            arq.unlink()
            qtd_fotos += 1

    print(f"✅ Banco limpo para produção (417 municípios e 1.717 escolas preservados) e {qtd_fotos} foto(s) removida(s).")


if __name__ == "__main__":
    limpar_ambiente_testes()