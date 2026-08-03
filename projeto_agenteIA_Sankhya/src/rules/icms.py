from typing import Dict, Any

# Fonte única de verdade: CFOP -> CSTs de ICMS permitidos para o fluxo de
# Uso e Consumo (TOP 1724). Além da validação abaixo, é reaproveitada pelo
# endpoint /regras-icms para montar os dropdowns de correção no front-end.
TABELA_DECISAO_CFOP_CST = {
    "1556": ["90", "51"], # Operações Internas
    "2556": ["00", "0", "90"],  # Operações Interestaduais
    "1407": ["60"],  # compra de mercadorias destinadas a uso ou consumo
    "2407": ["60", "10"],  # compra de mercadorias destinadas a uso ou consumo
    "1653": ["00","0","60", "61"], #Combustiveis
    "2653": ["00","0","60", "61"] #Combustiveis INTERESTADUAL
}


def validar_regras_icms_uso_consumo(cst: str, cfop: str, uf_origem: str) -> Dict[str, Any]:
    """
    Aplica regras de negócio para a conferência fiscal de NF-es de Entrada (Uso e Consumo - TOP 1724).

    :param cst: Código de Situação Tributária (ex: '00', '40', '90')
    :param cfop: Código Fiscal de Operações e Prestações (ex: '1556', '2556')
    :param uf_origem: Sigla da Unidade Federativa da empresa emitente (ex: 'SP')
    :return: Status de conformidade fiscal da linha e o motivo detalhado.
    """

    if cfop not in TABELA_DECISAO_CFOP_CST:
        return {
            "status": "REPROVADO",
            "motivo": f"CFOP '{cfop}' não autorizado para o fluxo de Uso e Consumo nesta operação."
        }

    csts_permitidos = TABELA_DECISAO_CFOP_CST[cfop]
    if cst not in csts_permitidos:
        return {
            "status": "REPROVADO",
            "motivo": f"CST '{cst}' incompatível com o CFOP '{cfop}'. Os CSTs aceitos são: {', '.join(csts_permitidos)}."
        }
        
    if cfop in ["2556", "2653"] and uf_origem == "EX": 
        return {
            "status": "REPROVADO",
            "motivo": "O CFOP '2556 ou 2653' (Interestadual) não deve ser utilizado em importações do exterior ('EX')."
        }
        
    return {
        "status": "APROVADO",
        "motivo": "Combinação de CFOP, CST e UF válida para as diretrizes fiscais da TOP 1724."
    }
