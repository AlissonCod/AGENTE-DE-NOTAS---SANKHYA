"""
Autenticação dos usuários do EucaVerify.

A identidade vem do Sankhya e a senha é do EucaVerify:

  * quem pode entrar, e com que nome, sai da TSIUSU — o usuário precisa
    existir, estar com acesso vigente (DTLIMACESSO) e pertencer a um dos
    grupos autorizados;
  * a senha é validada em src/local_auth.py.

Por que a senha não é a do Sankhya: foi testado contra este ambiente que
nenhuma via de validação está disponível para a aplicação. O gateway valida o
Sankhya ID e não a senha interna; MobileLoginSP.login responde
NullPointerException pelo gateway e também falando direto com o ERP, em JSON
e em XML; o /login do gateway exige um appkey que a empresa não possui; e
TSIUSU.INTERNO é bloqueada pelo DbExplorer. O login nativo da tela do ERP usa
DWR com JavaScript ofuscado de propósito, que não faz sentido replicar.

Como a lista de usuários continua saindo do Sankhya, tirar o acesso de alguém
no ERP (DTLIMACESSO ou troca de grupo) também tira o acesso aqui.
"""

import logging
import os
import re
from typing import Any, Dict, List, Optional

from src import local_auth
from src.client import SankhyaClient

logger = logging.getLogger(__name__)

# Grupos do Sankhya (TSIUSU.CODGRUPO) autorizados a usar o EucaVerify.
# Padrão: 7 = FISCAL, 14 = TECNOLOGIA. Como o agente grava UPDATE na TGFITE,
# manter isso restrito limita bastante a superfície de risco.
GRUPOS_PADRAO = "7,14"


def grupos_autorizados() -> List[int]:
    """Lê os grupos autorizados do ambiente, caindo no padrão FISCAL/TECNOLOGIA."""
    bruto = (os.getenv("EUCAVERIFY_GRUPOS") or "").strip() or GRUPOS_PADRAO

    grupos = []

    for pedaco in bruto.split(","):
        pedaco = pedaco.strip()

        if pedaco.isdigit():
            grupos.append(int(pedaco))
        elif pedaco:
            logger.warning("Grupo inválido em EUCAVERIFY_GRUPOS, ignorado: %r", pedaco)

    return grupos or [int(g) for g in GRUPOS_PADRAO.split(",")]


# Formato aceito para o login. Conferido contra a base real: além de letras e
# dígitos há usuários com espaço e parênteses ('ANA ROSA',
# 'PEDO.VERGILIO(JOHNDEERE)'), e o '@' entra porque o e-mail também é aceito
# como identificador. Aspas e ponto e vírgula ficam de fora.
PADRAO_IDENTIFICADOR = re.compile(r"^[A-Za-z0-9._\-()@ ]{1,60}$")

# O hífen simples é aceito ('SD-SANKHYA' existe na base), mas '--' não: foi
# verificado que o DbExplorerSP remove comentários '--' da query ANTES de
# repassá-la ao Oracle, o que corta o resto da linha junto com a aspa de
# fechamento (ORA-01756).
SEQUENCIA_PROIBIDA = "--"

MSG_CREDENCIAL_INVALIDA = "Usuário ou senha inválidos."
MSG_SEM_ACESSO = (
    "Este usuário não tem permissão para usar o EucaVerify. "
    "Procure o setor de Tecnologia."
)
MSG_PRIMEIRO_ACESSO = (
    "Você ainda não criou sua senha do EucaVerify. Use a opção de primeiro acesso."
)
MSG_ERRO_TECNICO = (
    "Não foi possível validar o login neste momento. Tente novamente."
)
MSG_AMBIGUO = (
    "Este e-mail está cadastrado para mais de um usuário no Sankhya. "
    "Entre com o seu nome de usuário em vez do e-mail."
)


def _escapar_literal_sql(valor: str) -> str:
    """Escapa aspas simples para uso dentro de um literal SQL.

    Em Oracle, o único caractere perigoso dentro de uma string entre aspas
    simples é a própria aspa; duplicá-la a torna literal.
    """
    return valor.replace("'", "''")


def identificador_valido(identificador: str) -> bool:
    """Valida o formato do login antes de qualquer uso em SQL."""
    identificador = str(identificador or "").strip()

    if not PADRAO_IDENTIFICADOR.match(identificador):
        return False

    return SEQUENCIA_PROIBIDA not in identificador


class IdentificadorAmbiguo(Exception):
    """Mais de um usuário responde pelo identificador informado.

    Acontece quando duas pessoas compartilham o mesmo e-mail na TSIUSU — o
    que existe nesta base (ALINE e KAREN dividem uma caixa do FISCAL). Se
    escolhêssemos uma delas, a sessão e a trilha de auditoria poderiam
    registrar a pessoa errada, que é justamente o que o login deve impedir.
    """


def buscar_usuario_autorizado(
    client: SankhyaClient, identificador: str
) -> Optional[Dict[str, Any]]:
    """Busca na TSIUSU um usuário com acesso vigente e grupo autorizado.

    Aceita tanto o NOMEUSU quanto o e-mail cadastrado. Devolve None quando o
    usuário não existe, está com o acesso expirado ou está fora dos grupos
    autorizados — os três casos recebem a mesma resposta para não revelar
    quais logins existem.

    :raises IdentificadorAmbiguo: quando o valor informado é um e-mail
        compartilhado por mais de um usuário.
    """
    from main import normalizar_linhas_sankhya

    chave = str(identificador).strip()
    chave_sql = _escapar_literal_sql(chave)
    grupos = ", ".join(str(g) for g in grupos_autorizados())

    sql = f"""
        SELECT
            USU.CODUSU,
            USU.NOMEUSU,
            USU.EMAIL,
            USU.CODGRUPO,
            GRU.NOMEGRUPO
        FROM TSIUSU USU
        LEFT JOIN TSIGRU GRU ON GRU.CODGRUPO = USU.CODGRUPO
        WHERE (UPPER(TRIM(USU.NOMEUSU)) = UPPER('{chave_sql}')
               OR UPPER(TRIM(USU.EMAIL)) = UPPER('{chave_sql}'))
          AND USU.CODGRUPO IN ({grupos})
          AND (USU.DTLIMACESSO IS NULL OR USU.DTLIMACESSO >= TRUNC(SYSDATE))
    """

    linhas = normalizar_linhas_sankhya(client.execute_sql(sql=sql))

    if not linhas:
        return None

    # O NOMEUSU é único, então bater com ele resolve qualquer ambiguidade.
    for linha in linhas:
        if str(linha.get("NOMEUSU") or "").strip().upper() == chave.upper():
            return linha

    if len(linhas) > 1:
        nomes = [str(l.get("NOMEUSU") or "").strip() for l in linhas]
        logger.warning(
            "E-mail compartilhado por %s usuários (%s). Exigindo o NOMEUSU.",
            len(linhas),
            ", ".join(nomes),
        )
        raise IdentificadorAmbiguo()

    return linhas[0]


def _montar_usuario(linha: Dict[str, Any]) -> Dict[str, Any]:
    """Converte a linha da TSIUSU no formato guardado na sessão."""
    codusu = linha.get("CODUSU")

    return {
        "nomeusu": str(linha.get("NOMEUSU") or "").strip(),
        "codusu": str(codusu).strip() if codusu is not None else "",
        "email": str(linha.get("EMAIL") or "").strip(),
        "grupo": str(linha.get("NOMEGRUPO") or "").strip(),
    }


def autenticar_usuario(
    client: SankhyaClient, identificador: str, senha: str
) -> Dict[str, Any]:
    """Valida login e senha para entrar no EucaVerify.

    :return: {"status": "APROVADO"|"REPROVADO"|"PRIMEIRO_ACESSO"|"ERRO_TECNICO",
              "mensagem": str, "usuario": {...}}
    """
    identificador = str(identificador or "").strip()
    senha = str(senha or "")

    if not identificador or not senha:
        return {"status": "REPROVADO", "mensagem": "Informe usuário e senha.", "usuario": {}}

    if not identificador_valido(identificador):
        logger.warning("Tentativa de login com identificador em formato inválido.")
        return {"status": "REPROVADO", "mensagem": MSG_CREDENCIAL_INVALIDA, "usuario": {}}

    try:
        linha = buscar_usuario_autorizado(client, identificador)
    except IdentificadorAmbiguo:
        return {"status": "REPROVADO", "mensagem": MSG_AMBIGUO, "usuario": {}}
    except Exception as e:
        logger.error("Falha ao consultar a TSIUSU no login: %s", e)
        return {"status": "ERRO_TECNICO", "mensagem": MSG_ERRO_TECNICO, "usuario": {}}

    if not linha:
        logger.info("Login recusado: '%s' não existe ou não é autorizado.", identificador)
        return {"status": "REPROVADO", "mensagem": MSG_CREDENCIAL_INVALIDA, "usuario": {}}

    usuario = _montar_usuario(linha)

    try:
        if not local_auth.tem_senha(usuario["nomeusu"]):
            return {
                "status": "PRIMEIRO_ACESSO",
                "mensagem": MSG_PRIMEIRO_ACESSO,
                "usuario": {},
            }

        if not local_auth.verificar_senha(usuario["nomeusu"], senha):
            logger.info("Senha incorreta para o usuário '%s'.", usuario["nomeusu"])
            return {
                "status": "REPROVADO",
                "mensagem": MSG_CREDENCIAL_INVALIDA,
                "usuario": {},
            }

    except Exception as e:
        logger.error("Falha ao verificar a senha local: %s", e)
        return {"status": "ERRO_TECNICO", "mensagem": MSG_ERRO_TECNICO, "usuario": {}}

    logger.info("Login aprovado para o usuário '%s'.", usuario["nomeusu"])

    return {
        "status": "APROVADO",
        "mensagem": "Login realizado com sucesso.",
        "usuario": usuario,
    }


def registrar_primeiro_acesso(
    client: SankhyaClient,
    identificador: str,
    email: str,
    senha: str,
    confirmacao: str,
) -> Dict[str, Any]:
    """Cria a senha do EucaVerify no primeiro acesso.

    Exige que a pessoa informe o e-mail cadastrado nela na TSIUSU. Sem isso,
    bastaria conhecer o nome de usuário de um colega para criar a senha dele e
    assinar correções no nome dele — o que anularia a trilha de auditoria.
    """
    identificador = str(identificador or "").strip()
    email = str(email or "").strip()

    if not identificador or not email:
        return {"status": "REPROVADO", "mensagem": "Informe usuário e e-mail.", "usuario": {}}

    if not identificador_valido(identificador):
        return {"status": "REPROVADO", "mensagem": MSG_CREDENCIAL_INVALIDA, "usuario": {}}

    erro_senha = local_auth.validar_forca_senha(senha, confirmacao)

    if erro_senha:
        return {"status": "REPROVADO", "mensagem": erro_senha, "usuario": {}}

    try:
        linha = buscar_usuario_autorizado(client, identificador)
    except IdentificadorAmbiguo:
        return {"status": "REPROVADO", "mensagem": MSG_AMBIGUO, "usuario": {}}
    except Exception as e:
        logger.error("Falha ao consultar a TSIUSU no primeiro acesso: %s", e)
        return {"status": "ERRO_TECNICO", "mensagem": MSG_ERRO_TECNICO, "usuario": {}}

    if not linha:
        return {"status": "REPROVADO", "mensagem": MSG_SEM_ACESSO, "usuario": {}}

    usuario = _montar_usuario(linha)
    email_cadastrado = usuario["email"]

    if not email_cadastrado:
        logger.warning(
            "Primeiro acesso barrado: '%s' não tem e-mail na TSIUSU.", usuario["nomeusu"]
        )
        return {
            "status": "REPROVADO",
            "mensagem": (
                "Seu usuário não tem e-mail cadastrado no Sankhya, então não é "
                "possível confirmar sua identidade por aqui. Procure a Tecnologia."
            ),
            "usuario": {},
        }

    if email.strip().upper() != email_cadastrado.strip().upper():
        logger.warning(
            "Primeiro acesso recusado para '%s': e-mail informado não confere.",
            usuario["nomeusu"],
        )
        return {
            "status": "REPROVADO",
            "mensagem": "O e-mail informado não confere com o cadastrado no Sankhya.",
            "usuario": {},
        }

    try:
        if local_auth.tem_senha(usuario["nomeusu"]):
            return {
                "status": "REPROVADO",
                "mensagem": (
                    "Este usuário já tem senha criada. Se você a esqueceu, "
                    "peça à Tecnologia para liberar um novo primeiro acesso."
                ),
                "usuario": {},
            }

        local_auth.definir_senha(
            nomeusu=usuario["nomeusu"], senha=senha, codusu=usuario["codusu"]
        )

    except Exception as e:
        logger.error("Falha ao gravar a senha do primeiro acesso: %s", e)
        return {"status": "ERRO_TECNICO", "mensagem": MSG_ERRO_TECNICO, "usuario": {}}

    logger.info("Primeiro acesso concluído para o usuário '%s'.", usuario["nomeusu"])

    return {
        "status": "APROVADO",
        "mensagem": "Senha criada com sucesso.",
        "usuario": usuario,
    }
