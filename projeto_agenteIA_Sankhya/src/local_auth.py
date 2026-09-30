"""
Armazenamento local das senhas do EucaVerify.

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
"""

import logging
import os
import sqlite3
from contextlib import contextmanager
from datetime import datetime
from typing import Optional

from werkzeug.security import check_password_hash, generate_password_hash

logger = logging.getLogger(__name__)

TAMANHO_MINIMO_SENHA = 8

_PASTA_PROJETO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
_CAMINHO_PADRAO = os.path.join(_PASTA_PROJETO, "dados", "eucaverify.db")


def caminho_banco() -> str:
    """Arquivo SQLite com as credenciais locais."""
    return (os.getenv("EUCAVERIFY_DB") or "").strip() or _CAMINHO_PADRAO


@contextmanager
def _conexao():
    """Abre o banco criando a pasta e o esquema, se ainda não existirem.

    SQLite em vez de um arquivo JSON porque o Gunicorn roda vários workers:
    dois logins simultâneos gravando no mesmo JSON corromperiam o arquivo,
    enquanto aqui o próprio banco cuida do bloqueio.
    """
    caminho = caminho_banco()
    os.makedirs(os.path.dirname(caminho), exist_ok=True)

    conexao = sqlite3.connect(caminho, timeout=10)
    conexao.row_factory = sqlite3.Row

    try:
        conexao.execute(
            """
            CREATE TABLE IF NOT EXISTS usuarios (
                nomeusu       TEXT PRIMARY KEY,
                codusu        TEXT,
                senha_hash    TEXT NOT NULL,
                criado_em     TEXT NOT NULL,
                atualizado_em TEXT NOT NULL,
                ultimo_acesso TEXT
            )
            """
        )
        yield conexao
        conexao.commit()
    finally:
        conexao.close()


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
