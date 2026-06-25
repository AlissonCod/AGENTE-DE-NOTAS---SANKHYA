import argparse
import json
import logging
import re
from typing import Any, Dict, List, Optional

from src.client import SankhyaClient
from src.rules.icms import validar_regras_icms_uso_consumo
from src.rules.icms import validar_regras_icms_uso_consumo
# ---------------------------------------------------------
# CONFIGURAÇÕES GERAIS
# ---------------------------------------------------------
TOP_ESPERADA = "1724"

logging.basicConfig(
    level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s"
)

logger = logging.getLogger(__name__)


# ---------------------------------------------------------
# FUNÇÕES UTILITÁRIAS
# ---------------------------------------------------------
def formatar_json(dados: Any) -> str:
    """Formata qualquer retorno em JSON legível para log."""
    try:
        return json.dumps(dados, indent=2, ensure_ascii=False, default=str)
    except Exception:
        return str(dados)


def resultado_padrao(
    status: str, mensagem: str, dados: Optional[Dict[str, Any]] = None
) -> Dict[str, Any]:
    """Padroniza a saída final do agente."""
    return {"status": status, "mensagem": mensagem, "dados": dados or {}}


def limpar_chave_nfe(chave: str) -> str:
    """Remove caracteres não numéricos e valida se a chave NF-e possui 44 dígitos."""
    chave_limpa = re.sub(r"\D", "", chave or "")

    if len(chave_limpa) != 44:
        raise ValueError(
            "Chave NF-e inválida. A chave deve conter exatamente 44 dígitos."
        )

    return chave_limpa


def limpar_numero(valor: Any, nome_campo: str) -> int:
    """Garante que um valor numérico usado em SQL seja realmente número."""
    valor_str = str(valor or "").strip()

    if not valor_str.isdigit():
        raise ValueError(f"{nome_campo} inválido: {valor}")

    return int(valor_str)


def get_campo(dados: Dict[str, Any], *nomes: str, default: Any = None) -> Any:
    """Busca campos ignorando diferença entre maiúsculas e minúsculas."""
    if not isinstance(dados, dict):
        return default

    normalizado = {str(k).upper(): v for k, v in dados.items()}

    for nome in nomes:
        valor = normalizado.get(str(nome).upper())

        if valor is not None:
            return valor

    return default


def normalizar_linhas_sankhya(resposta: Any) -> List[Dict[str, Any]]:
    """Normaliza diferentes formatos de retorno do Sankhya em uma lista de dicts.

    Suporta principalmente retornos como:

    {
        "responseBody": {
            "fieldsMetadata": [
                {"name": "NUNOTA"},
                {"name": "CHAVENFE"}
            ],
            "rows": [
                [123, "3126..."]
            ]
        }
    }

    Convertendo para:

    [
        {
            "NUNOTA": 123,
            "CHAVENFE": "3126..."
        }
    ]
    """

    if resposta is None:
        return []

    if isinstance(resposta, list):
        return [x for x in resposta if isinstance(x, dict)]

    if not isinstance(resposta, dict):
        return []

    body = resposta.get("responseBody", resposta)

    if isinstance(body, list):
        return [x for x in body if isinstance(x, dict)]

    if not isinstance(body, dict):
        return []

    # ---------------------------------------------------------
    # CASO PRINCIPAL DO DBEXPLORER:
    # fieldsMetadata + rows em lista de listas
    # ---------------------------------------------------------
    fields_metadata = body.get("fieldsMetadata")
    rows = body.get("rows")

    if isinstance(fields_metadata, list) and isinstance(rows, list):
        nomes_campos = []

        for campo in fields_metadata:
            if isinstance(campo, dict):
                nomes_campos.append(campo.get("name"))

        linhas_normalizadas = []

        for row in rows:
            if isinstance(row, dict):
                linhas_normalizadas.append(row)

            elif isinstance(row, list):
                linha_dict = {}

                for index, nome_campo in enumerate(nomes_campos):
                    if nome_campo and index < len(row):
                        linha_dict[nome_campo] = row[index]

                if linha_dict:
                    linhas_normalizadas.append(linha_dict)

        return linhas_normalizadas

    # ---------------------------------------------------------
    # CASO rows JÁ SEJA LISTA DE DICTS
    # ---------------------------------------------------------
    if isinstance(rows, list):
        return [x for x in rows if isinstance(x, dict)]

    # ---------------------------------------------------------
    # OUTROS FORMATOS POSSÍVEIS DO CRUD
    # ---------------------------------------------------------
    possiveis_caminhos = [
        body.get("records"),
        body.get("record"),
        body.get("result"),
        (
            body.get("resultSet", {}).get("rows")
            if isinstance(body.get("resultSet"), dict)
            else None
        ),
        (
            body.get("entities", {}).get("entity")
            if isinstance(body.get("entities"), dict)
            else None
        ),
    ]

    for caminho in possiveis_caminhos:
        if caminho is None:
            continue

        if isinstance(caminho, list):
            return [x for x in caminho if isinstance(x, dict)]

        if isinstance(caminho, dict):
            return [caminho]

    # Caso o próprio responseBody já seja uma linha
    if any(
        str(k).upper() in ["NUNOTA", "CHAVENFE", "CODTIPOPER"]
        for k in body.keys()
    ):
        return [body]

    return []


# ---------------------------------------------------------
# MOTOR DE REGRAS
# ---------------------------------------------------------
def testar_motor_regras() -> bool:
    """Testa localmente o motor de regras fiscais ICMS."""
    logger.info("--- Testando Motor de Regras ICMS ---")

    try:
        cenarios = [
            {
                "nome": "Cenário válido - CFOP 1556 / CST 00 / UF SP",
                "cst": "00",
                "cfop": "1556",
                "uf_origem": "SP",
            },
            {
                "nome": "Cenário inválido - CFOP 2556 / CST 00 / UF EX",
                "cst": "00",
                "cfop": "2556",
                "uf_origem": "EX",
            },
        ]

        for cenario in cenarios:
            retorno = validar_regras_icms_uso_consumo(
                cst=cenario["cst"],
                cfop=cenario["cfop"],
                uf_origem=cenario["uf_origem"],
            )

            logger.info("%s:\n%s", cenario["nome"], formatar_json(retorno))

        logger.info("Motor de regras executado com sucesso.")
        return True

    except Exception as e:
        logger.error("Falha no motor de regras ICMS: %s", e)
        return False


# ---------------------------------------------------------
# AUTENTICAÇÃO
# ---------------------------------------------------------
def autenticar_sankhya() -> Optional[SankhyaClient]:
    """Tenta autenticar na API Sankhya."""
    logger.info("--- Autenticando na API SankhyaW ---")

    try:
        client = SankhyaClient()
        logger.info("Autenticação realizada com sucesso.")
        return client

    except Exception as e:
        logger.error("Erro crítico de autenticação: %s", e)
        return None


# ---------------------------------------------------------
# PLANO A - CRUD
# ---------------------------------------------------------
def testar_plano_a_crud(client: SankhyaClient) -> bool:
    """Diagnóstico do Plano A usando CRUDServiceProvider.loadRecords."""
    logger.info("--- Plano A: Testando conexão via CRUD ---")

    try:
        resposta = client.load_records(entity_name="CabecalhoNota")

        response_body = resposta.get("responseBody", resposta)

        logger.info("SUCESSO Plano A: Conexão via CRUD estabelecida.")
        logger.info("Dados retornados via CRUD:\n%s", formatar_json(response_body))

        return True

    except Exception as e:
        logger.warning("Plano A falhou. Erro retornado: %s", e)
        return False


def buscar_cabecalho_plano_a(
    client: SankhyaClient, chave_nfe: str
) -> Optional[Dict[str, Any]]:
    """Plano A:

    Busca o cabeçalho da NF-e via CRUDServiceProvider.loadRecords.

    Se seu client.load_records ainda não aceitar criteria_expression/result_fields,
    essa função falhará e o fluxo seguirá para o Plano B.
    """
    logger.info("--- Plano A: Buscando NF-e via CRUD ---")

    try:
        # Monta o critério no formato que a função load_records espera
        criteria = {
            "expression": {"$": f"this.CHAVENFE = '{chave_nfe}'"}
        }

        resposta = client.load_records(
            entity_name="CabecalhoNota",
            criteria=criteria,
            result_fields=[
                "NUNOTA",
                "CHAVENFE",
                "CODTIPOPER",
                "NUMNOTA",
                "SERIENOTA",
                "DTNEG",
                "CODPARC",
                "NOMEPARC",
                "VLRNOTA",
            ],
        )

        linhas = normalizar_linhas_sankhya(resposta)

        if not linhas:
            logger.warning(
                "Plano A executou, mas não encontrou NF-e para a chave informada."
            )
            return None

        logger.info("Plano A encontrou a NF-e com sucesso.")
        logger.info("Cabeçalho Plano A:\n%s", formatar_json(linhas[0]))

        return linhas[0]

    except Exception as e:
        logger.warning("Plano A falhou ao buscar cabeçalho da NF-e: %s", e)
        return None


def buscar_itens_plano_a(
    client: SankhyaClient, nunota: int
) -> List[Dict[str, Any]]:
    """Plano A:

    Busca os itens da NF-e via CRUDServiceProvider.loadRecords.
    """
    logger.info("--- Plano A: Buscando itens via CRUD ---")

    try:
        criteria = {
            "expression": {"$": f"this.NUNOTA = {nunota}"}
        }

        resposta = client.load_records(
            entity_name="ItemNota",
            criteria=criteria,
            result_fields=[
                "NUNOTA",
                "SEQUENCIA",
                "CODPROD",
                "DESCRPROD",
                "CODCFO",      # Alias para CFOP
                "CODTRIB",     # Alias para CSTICMS
                "QTDNEG",
                "VLRUNIT",
                "VLRTOT",
                "UFORIGEM",
            ],
        )

        linhas = normalizar_linhas_sankhya(resposta)

        logger.info("Plano A retornou %s item(ns).", len(linhas))

        return linhas

    except Exception as e:
        logger.warning("Plano A falhou ao buscar itens da NF-e: %s", e)
        return []


# ---------------------------------------------------------
# PLANO B - SQL DIRETO / DBEXPLORER
# ---------------------------------------------------------
def testar_plano_b_conexao(client: SankhyaClient) -> bool:
    """Diagnóstico do Plano B usando DbExplorerSP.executeQuery."""
    logger.info("--- Plano B: Testando conexão via SQL Direto ---")

    try:
        sql = """
            SELECT MAX(NUNOTA) AS ULTIMA_NOTA
            FROM TGFCAB
        """

        resposta = client.execute_sql(sql=sql)

        logger.info(
            "Plano B conexão OK:\n%s",
            formatar_json(resposta.get("responseBody", resposta)),
        )

        linhas = normalizar_linhas_sankhya(resposta)

        if linhas:
            logger.info("Plano B normalizado:\n%s", formatar_json(linhas))

        return True

    except Exception as e:
        logger.error("Plano B conexão falhou: %s", e)
        return False


def buscar_cabecalho_plano_b(
    client: SankhyaClient, chave_nfe: str
) -> Optional[Dict[str, Any]]:
    """Plano B:

    Busca cabeçalho da NF-e diretamente na TGFCAB via SQL.
    """
    logger.info("--- Plano B: Buscando NF-e via SQL Direto ---")
    try:
        # 1. Limpa e valida a chave para garantir que contém apenas 44 dígitos numéricos
        chave_segura = limpar_chave_nfe(chave_nfe)

        # 2. Monta o SQL com a chave já validada e segura
        sql = f"""
            SELECT
                CAB.NUNOTA,
                CAB.CODTIPOPER,
                CAB.NUMNOTA,
                CAB.SERIENOTA,
                CAB.DTNEG,
                CAB.CODPARC,
                PAR.NOMEPARC,
                CAB.VLRNOTA
            FROM 
                TGFCAB CAB
            INNER JOIN 
                TGFPAR PAR ON PAR.CODPARC = CAB.CODPARC
            WHERE 
                TRIM(CAB.CHAVENFE) = '{chave_segura}'
        """

        resposta = client.execute_sql(sql=sql)
        linhas = normalizar_linhas_sankhya(resposta)

        if not linhas:
            logger.warning(
                "Plano B executou, mas não encontrou NF-e para a chave informada."
            )
            return None

        logger.info("Plano B encontrou a NF-e com sucesso.")
        logger.info("Cabeçalho Plano B:\n%s", formatar_json(linhas[0]))

        return linhas[0]

    except Exception as e:
        logger.error("Plano B falhou ao buscar cabeçalho da NF-e: %s", e)
        return None


def buscar_itens_plano_b(
    client: SankhyaClient, nunota: int
) -> List[Dict[str, Any]]:
    """Plano B:

    Busca itens da NF-e diretamente na TGFITE via SQL.
    """
    logger.info("--- Plano B: Buscando itens via SQL Direto ---")

    try:
        nunota_segura = limpar_numero(nunota, "NUNOTA")

        sql = f"""
            SELECT
                ITE.NUNOTA,
                ITE.SEQUENCIA,
                ITE.CODPROD,
                PRO.DESCRPROD,
                ITE.CODCFO AS CFOP,
                ITE.CODTRIB AS CSTICMS,
                ITE.QTDNEG,
                ITE.VLRUNIT,
                ITE.VLRTOT
            FROM TGFITE ITE
            LEFT JOIN TGFPRO PRO ON PRO.CODPROD = ITE.CODPROD
            WHERE ITE.NUNOTA = {nunota_segura}
            ORDER BY ITE.SEQUENCIA
        """

        resposta = client.execute_sql(sql=sql)
        linhas = normalizar_linhas_sankhya(resposta)

        logger.info("Plano B retornou %s item(ns).", len(linhas))

        if linhas:
            logger.info("Primeiro item Plano B:\n%s", formatar_json(linhas[0]))

        return linhas

    except Exception as e:
        logger.error("Plano B falhou ao buscar itens da NF-e: %s", e)
        return []


# ---------------------------------------------------------
# BUSCAS COM FALLBACK PLANO A -> PLANO B
# ---------------------------------------------------------
def buscar_cabecalho_nfe(client: SankhyaClient, chave_nfe: str) -> Dict[str, Any]:
    """Busca cabeçalho usando Plano A.

    Se falhar ou não retornar dados, usa Plano B.
    """
    cabecalho = buscar_cabecalho_plano_a(client, chave_nfe)

    if cabecalho:
        return {"origem_consulta": "PLANO_A_CRUD", "dados": cabecalho}

    logger.info("Plano A não retornou cabeçalho. Acionando Plano B.")

    cabecalho = buscar_cabecalho_plano_b(client, chave_nfe)

    if cabecalho:
        return {"origem_consulta": "PLANO_B_SQL", "dados": cabecalho}

    return {"origem_consulta": "NAO_ENCONTRADO", "dados": {}}


def buscar_itens_nfe(client: SankhyaClient, nunota: int) -> Dict[str, Any]:
    """Busca itens usando Plano A.

    Se falhar ou não retornar dados, usa Plano B.
    """
    itens = buscar_itens_plano_a(client, nunota)

    if itens:
        return {"origem_consulta": "PLANO_A_CRUD", "dados": itens}

    logger.info("Plano A não retornou itens. Acionando Plano B.")

    itens = buscar_itens_plano_b(client, nunota)

    if itens:
        return {"origem_consulta": "PLANO_B_SQL", "dados": itens}

    return {"origem_consulta": "NAO_ENCONTRADO", "dados": []}


# ---------------------------------------------------------
# VALIDAÇÕES FISCAIS
# ---------------------------------------------------------
def validar_top_1724(cabecalho: Dict[str, Any]) -> Dict[str, Any]:
    """Valida se a NF-e pertence à TOP esperada."""
    top_encontrada = str(
        get_campo(cabecalho, "CODTIPOPER", "TOP", default="")
    ).strip()

    if top_encontrada == TOP_ESPERADA:
        return {
            "status": "APROVADO",
            "regra": "REGRA_TOP_1724_001",
            "campo": "CODTIPOPER",
            "valor_encontrado": top_encontrada,
            "valor_esperado": TOP_ESPERADA,
            "mensagem": "NF-e pertence à TOP 1724.",
        }

    return {
        "status": "FORA_DO_ESCOPO",
        "regra": "REGRA_TOP_1724_001",
        "campo": "CODTIPOPER",
        "valor_encontrado": top_encontrada,
        "valor_esperado": TOP_ESPERADA,
        "mensagem": "NF-e não pertence à TOP 1724.",
    }


def validar_itens_icms(
    chave_nfe: str, nunota: int, itens: List[Dict[str, Any]]
) -> Dict[str, Any]:
    """Valida ICMS item por item usando o motor de regras fiscal."""
    validacoes = []
    divergencias = []
    revisoes = []

    for item in itens:
        sequencia = get_campo(item, "SEQUENCIA")
        codprod = get_campo(item, "CODPROD")
        descrprod = get_campo(item, "DESCRPROD")
        cfop = str(get_campo(item, "CFOP", "CODCFO", default="")).strip()
        cst = str(get_campo(item, "CSTICMS", "CODTRIB", default="")).strip()
        uf_origem = str(
            get_campo(item, "UFORIGEM", "UF_ORIGEM", default="")
        ).strip()
        qtd = get_campo(item, "QTDNEG", default=0)
        vlr_unit = get_campo(item, "VLRUNIT", default=0)
        vlr_tot = get_campo(item, "VLRTOT", default=0)

        log_base = {
            "chave_nfe": chave_nfe,
            "nunota": nunota,
            "sequencia": sequencia,
            "codprod": codprod,
            "descrprod": descrprod,
            "cfop": cfop,
            "cst_icms": cst,
            "uf_origem": uf_origem,
            "quantidade": qtd,
            "valor_unitario": vlr_unit,
            "valor_total": vlr_tot,
        }

        if not cfop:
            revisoes.append({
                **log_base,
                "status": "REVISAO_MANUAL",
                "regra": "REGRA_ICMS_1724_CFOP_OBRIGATORIO",
                "mensagem": "Item sem CFOP retornado pela consulta.",
            })
            continue

        if not cst:
            revisoes.append({
                **log_base,
                "status": "REVISAO_MANUAL",
                "regra": "REGRA_ICMS_1724_CST_OBRIGATORIO",
                "mensagem": "Item sem CST ICMS retornado pela consulta.",
            })
            continue

        retorno_regra = validar_regras_icms_uso_consumo(
            cst=cst, cfop=cfop, uf_origem=uf_origem
        )

        status_regra = str(retorno_regra.get("status", "")).upper()

        log_decisao = {
            **log_base,
            "regra": "REGRA_ICMS_1724_USO_CONSUMO",
            "resultado_regra": retorno_regra,
        }

        if status_regra == "APROVADO":
            validacoes.append({**log_decisao, "status": "APROVADO"})

        elif status_regra in ["REVISAO_MANUAL", "REVISÃO_MANUAL"]:
            revisoes.append({**log_decisao, "status": "REVISAO_MANUAL"})

        else:
            divergencias.append({**log_decisao, "status": "DIVERGENTE"})

    if divergencias:
        status_final = "DIVERGENTE"
    elif revisoes:
        status_final = "REVISAO_MANUAL"
    else:
        status_final = "APROVADO"

    return {
        "status": status_final,
        "total_itens": len(itens),
        "total_aprovados": len(validacoes),
        "total_divergentes": len(divergencias),
        "total_revisao_manual": len(revisoes),
        "validacoes": validacoes,
        "divergencias": divergencias,
        "revisoes": revisoes,
    }


# ---------------------------------------------------------
# PROCESSAMENTO DA NF-e
# ---------------------------------------------------------
def processar_nfe(client: SankhyaClient, chave_nfe: str) -> Dict[str, Any]:
    """Processa uma NF-e específica pela chave de acesso."""
    logger.info("Iniciando processamento da NF-e: %s", chave_nfe)

    consulta_cabecalho = buscar_cabecalho_nfe(client, chave_nfe)
    cabecalho = consulta_cabecalho["dados"]

    if not cabecalho:
        return resultado_padrao(
            status="DIVERGENTE",
            mensagem="NF-e não encontrada no Sankhya para a chave informada.",
            dados={
                "chave_nfe": chave_nfe,
                "origem_consulta": consulta_cabecalho["origem_consulta"],
            },
        )

    nunota = get_campo(cabecalho, "NUNOTA")
    nunota = limpar_numero(nunota, "NUNOTA")

    validacao_top = validar_top_1724(cabecalho)

    if validacao_top["status"] != "APROVADO":
        return resultado_padrao(
            status="FORA_DO_ESCOPO",
            mensagem="NF-e encontrada, porém está fora do escopo da TOP 1724.",
            dados={
                "chave_nfe": chave_nfe,
                "nunota": nunota,
                "cabecalho": cabecalho,
                "origem_cabecalho": consulta_cabecalho["origem_consulta"],
                "validacao_top": validacao_top,
            },
        )

    consulta_itens = buscar_itens_nfe(client, nunota)
    itens = consulta_itens["dados"]

    if not itens:
        return resultado_padrao(
            status="DIVERGENTE",
            mensagem="NF-e encontrada e TOP validada, mas nenhum item foi retornado.",
            dados={
                "chave_nfe": chave_nfe,
                "nunota": nunota,
                "cabecalho": cabecalho,
                "origem_cabecalho": consulta_cabecalho["origem_consulta"],
                "origem_itens": consulta_itens["origem_consulta"],
                "validacao_top": validacao_top,
            },
        )

    validacao_icms = validar_itens_icms(
        chave_nfe=chave_nfe, nunota=nunota, itens=itens
    )

    status_final = validacao_icms["status"]

    if status_final == "APROVADO":
        mensagem = "NF-e TOP 1724 aprovada nas validações iniciais de ICMS."
    elif status_final == "REVISAO_MANUAL":
        mensagem = (
            "NF-e TOP 1724 precisa de revisão manual em um ou mais itens."
        )
    else:
        mensagem = "NF-e TOP 1724 possui divergências fiscais nos itens."

    return resultado_padrao(
        status=status_final,
        mensagem=mensagem,
        dados={
            "chave_nfe": chave_nfe,
            "nunota": nunota,
            "cabecalho": cabecalho,
            "origem_cabecalho": consulta_cabecalho["origem_consulta"],
            "origem_itens": consulta_itens["origem_consulta"],
            "validacao_top": validacao_top,
            "validacao_icms": validacao_icms,
        },
    )


# ---------------------------------------------------------
# MODO DIAGNÓSTICO
# ---------------------------------------------------------
def executar_diagnostico(client: SankhyaClient) -> Dict[str, Any]:
    """Executa testes técnicos quando nenhuma CHAVENFE for informada."""
    logger.info("Executando modo diagnóstico sem CHAVENFE.")

    plano_a_ok = testar_plano_a_crud(client)
    plano_b_ok = testar_plano_b_conexao(client)

    if plano_a_ok or plano_b_ok:
        status = "APROVADO"
        mensagem = "Diagnóstico técnico executado. Pelo menos um plano de consulta funcionou."
    else:
        status = "ERRO_TECNICO"
        mensagem = "Diagnóstico técnico executado, mas Plano A e Plano B falharam."

    return resultado_padrao(
        status=status,
        mensagem=mensagem,
        dados={"plano_a_crud": plano_a_ok, "plano_b_sql": plano_b_ok},
    )


# ---------------------------------------------------------
# MAIN
# ---------------------------------------------------------
def main():
    parser = argparse.ArgumentParser(
        description="Agente IA Sankhya - Conferência Fiscal NF-e TOP 1724"
    )

    parser.add_argument(
        "--chave",
        required=False,
        help="Chave de acesso da NF-e com 44 dígitos. Se não informar, executa apenas diagnóstico técnico.",
    )

    args = parser.parse_args()

    logger.info("Iniciando Agente IA Sankhya - TOP 1724")

    motor_ok = testar_motor_regras()

    if not motor_ok:
        resultado = resultado_padrao(
            status="ERRO_TECNICO",
            mensagem="Falha ao iniciar motor de regras ICMS.",
        )
        logger.error("Resultado final:\n%s", formatar_json(resultado))
        return

    client = autenticar_sankhya()

    if client is None:
        resultado = resultado_padrao(
            status="ERRO_TECNICO",
            mensagem="Falha na autenticação com a API Sankhya.",
        )
        logger.error("Resultado final:\n%s", formatar_json(resultado))
        return

    try:
        if not args.chave:
            resultado = executar_diagnostico(client)
            logger.info("Resultado final:\n%s", formatar_json(resultado))
            return

        chave_nfe = limpar_chave_nfe(args.chave)

        resultado = processar_nfe(client=client, chave_nfe=chave_nfe)

        if resultado["status"] == "APROVADO":
            logger.info("Resultado final:\n%s", formatar_json(resultado))

        elif resultado["status"] in ["REVISAO_MANUAL", "FORA_DO_ESCOPO"]:
            logger.warning("Resultado final:\n%s", formatar_json(resultado))

        else:
            logger.error("Resultado final:\n%s", formatar_json(resultado))

    except Exception as e:
        resultado = resultado_padrao(
            status="ERRO_TECNICO",
            mensagem=f"Erro inesperado no processamento: {e}",
        )
        logger.error("Resultado final:\n%s", formatar_json(resultado))


if __name__ == "__main__":
    main()