"""
Armazenamento das senhas do EucaVerify.

Por que as senhas são daqui e não do Sankhya: foi verificado contra este
ambiente que nenhuma via de validação da senha do ERP está disponível para a
aplicação —

  * o gateway (api.sankhya.com.br) valida o Sankhya ID, não a senha interna;
  * MobileLoginSP.login devolve NullPointerException, tanto pelo gateway
    quanto falando direto com o ERP, em JSON e em XML;
  * o endpoint /login do gateway exige um appkey que a empresa não possui;
  * TSIUSU.INTERNO é bloqueada pelo DbExplorer ("Consulta sem nível de
    segurança"), então nem o hash dá para conferir.

Quem a pessoa é continua vindo do Sankhya (TSIUSU: existência, grupo e
validade do acesso). O que mora aqui é apenas a senha do EucaVerify.

As senhas nunca são gravadas em texto puro: guardamos o hash do Werkzeug
(scrypt por padrão), que já vem junto com o Flask.

Onde essa tabela mora depende do ambiente:

  * havendo EUCAVERIFY_DATABASE_URL (ou DATABASE_URL), num Postgres — é o
    caso em produção. O disco do serviço no Render é apagado a cada deploy,
    restart e hibernação, então um arquivo local levaria as senhas embora e a
    equipe cairia no primeiro acesso a cada publicação;
  * sem essa variável, no SQLite de dados/eucaverify.db, que continua sendo o
    caminho cômodo para desenvolvimento local.

O esquema e as consultas são os mesmos nos dois bancos. A única diferença de
sintaxe que nos afeta é o marcador de parâmetro, resolvida em _Conexao.
"""

import logging
import os
import sqlite3
import threading
from contextlib import contextmanager
from datetime import datetime
from typing import Optional

from werkzeug.security import check_password_hash, generate_password_hash

logger = logging.getLogger(__name__)

TAMANHO_MINIMO_SENHA = 8

_PASTA_PROJETO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
_CAMINHO_PADRAO = os.path.join(_PASTA_PROJETO, "dados", "eucaverify.db")

_ESQUEMA = """
    CREATE TABLE IF NOT EXISTS usuarios (
        nomeusu       TEXT PRIMARY KEY,
        codusu        TEXT,
        senha_hash    TEXT NOT NULL,
        criado_em     TEXT NOT NULL,
        atualizado_em TEXT NOT NULL,
        ultimo_acesso TEXT
    )
"""

# Chave arbitrária e fixa do advisory lock que serializa a criação do esquema
# no Postgres. Ver _garantir_esquema.
_TRAVA_ESQUEMA_POSTGRES = 827364501

# O esquema só precisa ser conferido uma vez por processo; sem isso, cada
# login pagaria um DDL à toa, o que num banco remoto custa uma ida e volta.
_esquema_conferido = False
_trava_esquema = threading.Lock()


def url_postgres() -> str:
    """URL de conexão do Postgres, ou string vazia para usar o SQLite.

    EUCAVERIFY_DATABASE_URL tem precedência para permitir apontar este banco
    para um servidor diferente do que o resto da aplicação usaria, mas o
    DATABASE_URL padrão (que é o nome que Neon e Render já entregam) basta.
    """
    return (
        os.getenv("EUCAVERIFY_DATABASE_URL") or os.getenv("DATABASE_URL") or ""
    ).strip()


def usando_postgres() -> bool:
    """Informa se as senhas estão num Postgres em vez do arquivo local."""
    return bool(url_postgres())


def caminho_banco() -> str:
    """Arquivo SQLite usado quando não há Postgres configurado."""
    return (os.getenv("EUCAVERIFY_DB") or "").strip() or _CAMINHO_PADRAO


def descricao_armazenamento() -> str:
    """Resume onde as senhas estão, para log e para a tela de administração."""
    if not usando_postgres():
        return f"SQLite em {caminho_banco()}"

    # A URL carrega a senha do banco, então nunca vai inteira para o log.
    url = url_postgres()
    servidor = url.split("@")[-1].split("?")[0] if "@" in url else "servidor remoto"

    return f"Postgres em {servidor}"


class _Conexao:
    """Envelope fino que faz o mesmo SQL servir aos dois bancos.

    O sqlite3 marca parâmetro com '?' e o psycopg com '%s'. Escrevemos tudo
    com '?' e traduzimos aqui; nenhuma consulta deste módulo tem '?' dentro de
    literal, então a troca é segura. Os valores seguem parametrizados — em
    momento algum são interpolados no SQL.
    """

    def __init__(self, conexao, postgres: bool):
        self._conexao = conexao
        self._postgres = postgres

    def execute(self, sql: str, params=()):
        if self._postgres:
            sql = sql.replace("?", "%s")

        return self._conexao.execute(sql, params)


def _garantir_esquema(conexao: _Conexao, postgres: bool) -> None:
    """Cria a tabela na primeira conexão do processo.

    No Postgres, CREATE TABLE IF NOT EXISTS não protege contra dois workers
    do Gunicorn criando a tabela no mesmo instante — o índice interno do
    catálogo acusa duplicidade. O advisory lock faz o segundo esperar e, ao
    chegar sua vez, encontrar a tabela já pronta. Ele é liberado no commit.
    """
    global _esquema_conferido

    if _esquema_conferido:
        return

    with _trava_esquema:
        if _esquema_conferido:
            return

        if postgres:
            conexao.execute(
                "SELECT pg_advisory_xact_lock(?)", (_TRAVA_ESQUEMA_POSTGRES,)
            )

        conexao.execute(_ESQUEMA)
        _esquema_conferido = True


def _conectar_postgres(url: str):
    """Abre a conexão com o Postgres, exigindo TLS.

    O Neon só aceita conexão cifrada e já entrega a URL com sslmode, mas
    completamos quando ela vem sem — assim uma URL copiada pela metade falha
    com erro claro de credencial em vez de trafegar a senha em texto puro.
    """
    import psycopg
    from psycopg.rows import dict_row

    if "sslmode=" not in url:
        url += ("&" if "?" in url else "?") + "sslmode=require"

    # O Neon hiberna o compute quando ninguém usa; a primeira conexão depois
    # disso espera o banco acordar, o que costuma levar poucos segundos.
    return psycopg.connect(url, row_factory=dict_row, connect_timeout=15)


def _conectar_sqlite():
    """Abre o SQLite, criando a pasta se ainda não existir.

    SQLite em vez de um arquivo JSON porque o Gunicorn roda vários workers:
    dois logins simultâneos gravando no mesmo JSON corromperiam o arquivo,
    enquanto aqui o próprio banco cuida do bloqueio.
    """
    caminho = caminho_banco()
    os.makedirs(os.path.dirname(caminho), exist_ok=True)

    conexao = sqlite3.connect(caminho, timeout=10)
    conexao.row_factory = sqlite3.Row

    return conexao


@contextmanager
def _conexao():
    """Entrega uma conexão pronta, com o esquema garantido, e faz o commit."""
    postgres = usando_postgres()
    bruta = _conectar_postgres(url_postgres()) if postgres else _conectar_sqlite()
    conexao = _Conexao(bruta, postgres)

    try:
        _garantir_esquema(conexao, postgres)
        yield conexao
        bruta.commit()
    except Exception:
        bruta.rollback()
        raise
    finally:
        bruta.close()


def _chave(nomeusu: str) -> str:
    """Normaliza o login para servir de chave primária.

    O NOMEUSU do Sankhya não distingue maiúsculas de minúsculas na prática,
    então guardamos sempre em caixa alta para não criar duas contas para a
    mesma pessoa ('alisson.junior' e 'ALISSON.JUNIOR').
    """
    return str(nomeusu or "").strip().upper()


def tem_senha(nomeusu: str) -> bool:
    """Informa se o usuário já passou pelo primeiro acesso."""
    with _conexao() as conexao:
        linha = conexao.execute(
            "SELECT 1 FROM usuarios WHERE nomeusu = ?", (_chave(nomeusu),)
        ).fetchone()

    return linha is not None


def definir_senha(nomeusu: str, senha: str, codusu: Optional[str] = None) -> None:
    """Cria ou substitui a senha local do usuário."""
    agora = datetime.now().isoformat(timespec="seconds")
    chave = _chave(nomeusu)
    senha_hash = generate_password_hash(senha)

    with _conexao() as conexao:
        conexao.execute(
            """
            INSERT INTO usuarios (nomeusu, codusu, senha_hash, criado_em, atualizado_em)
            VALUES (?, ?, ?, ?, ?)
            ON CONFLICT(nomeusu) DO UPDATE SET
                senha_hash    = excluded.senha_hash,
                codusu        = COALESCE(excluded.codusu, usuarios.codusu),
                atualizado_em = excluded.atualizado_em
            """,
            (chave, str(codusu) if codusu is not None else None, senha_hash, agora, agora),
        )

    logger.info("Senha do EucaVerify definida para o usuário '%s'.", chave)


def verificar_senha(nomeusu: str, senha: str) -> bool:
    """Confere a senha informada contra o hash guardado."""
    chave = _chave(nomeusu)

    with _conexao() as conexao:
        linha = conexao.execute(
            "SELECT senha_hash FROM usuarios WHERE nomeusu = ?", (chave,)
        ).fetchone()

        if linha is None:
            return False

        if not check_password_hash(linha["senha_hash"], senha):
            return False

        conexao.execute(
            "UPDATE usuarios SET ultimo_acesso = ? WHERE nomeusu = ?",
            (datetime.now().isoformat(timespec="seconds"), chave),
        )

    return True


def validar_forca_senha(senha: str, confirmacao: str) -> Optional[str]:
    """Valida a senha escolhida. Devolve a mensagem de erro, ou None se estiver boa."""
    senha = str(senha or "")

    if len(senha) < TAMANHO_MINIMO_SENHA:
        return f"A senha precisa ter pelo menos {TAMANHO_MINIMO_SENHA} caracteres."

    if senha != str(confirmacao or ""):
        return "As duas senhas não conferem."

    if senha.strip() == "":
        return "A senha não pode ser só espaços."

    return None


def remover_usuario(nomeusu: str) -> bool:
    """Apaga a senha local, devolvendo o usuário ao estado de primeiro acesso.

    Usado quando alguém esquece a senha: o administrador remove o registro e a
    pessoa cadastra outra confirmando o e-mail dela na TSIUSU.
    """
    with _conexao() as conexao:
        cursor = conexao.execute(
            "DELETE FROM usuarios WHERE nomeusu = ?", (_chave(nomeusu),)
        )
        removeu = cursor.rowcount > 0

    if removeu:
        logger.info("Senha local removida para o usuário '%s'.", _chave(nomeusu))

    return removeu


def listar_usuarios() -> list:
    """Lista quem já criou senha, para conferência administrativa."""
    with _conexao() as conexao:
        linhas = conexao.execute(
            "SELECT nomeusu, codusu, criado_em, atualizado_em, ultimo_acesso "
            "FROM usuarios ORDER BY nomeusu"
        ).fetchall()

    return [dict(linha) for linha in linhas]
