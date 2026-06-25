import logging
from flask import Flask, jsonify, render_template, request, send_file
import time
import pandas as pd
import io

# Importa as funções de negócio do script principal
from main import autenticar_sankhya, limpar_chave_nfe, processar_nfe, normalizar_linhas_sankhya

logger = logging.getLogger(__name__)

# ---------------------------------------------------------
# INICIALIZAÇÃO DO FLASK E CLIENTE SANKHYA
# ---------------------------------------------------------

app = Flask(__name__, template_folder='.')
sankhya_client = None


def inicializar_cliente_sankhya():
    """
    Autentica na API Sankhya e armazena o cliente globalmente.
    Esta função é chamada uma vez antes da primeira requisição.
    
    """
    global sankhya_client
    if sankhya_client is None:
        logger.info("Inicializando cliente Sankhya para a aplicação Flask...")
        sankhya_client = autenticar_sankhya()
        if sankhya_client:
            logger.info("Cliente Sankhya autenticado e pronto para uso.")
        else:
            logger.error("FALHA CRÍTICA: Não foi possível autenticar o cliente Sankhya na inicialização.")


@app.before_request
def before_first_request_func():
    inicializar_cliente_sankhya()

# ---------------------------------------------------------
# ROTAS DA APLICAÇÃO
# ---------------------------------------------------------

@app.route("/")
def index():
    """Renderiza a página HTML principal da interface."""
    return render_template("index.html")


@app.route("/validar", methods=["POST"])
def validar_nfe():
    """Endpoint da API para validar a chave NF-e."""
    dados = request.get_json()
    if not dados or "chave" not in dados:
        return jsonify({"erro": "A chave da NF-e não foi fornecida."}), 400

    if not sankhya_client:
        return jsonify({"erro": "Erro crítico: Cliente Sankhya não está autenticado."}), 503

    try:
        chave_limpa = limpar_chave_nfe(dados["chave"])
        resultado = processar_nfe(client=sankhya_client, chave_nfe=chave_limpa)
        return jsonify(resultado)
    except ValueError as e:
        return jsonify({"status": "ERRO_VALIDACAO", "mensagem": str(e)}), 400
    except Exception as e:
        logger.error(f"Erro inesperado ao processar a chave: {e}", exc_info=True)
        return jsonify({"status": "ERRO_TECNICO", "mensagem": f"Erro inesperado no servidor: {e}"}), 500


def buscar_chaves_pendentes_no_banco(data_inicio: str, data_fim: str):
    """
    Busca no banco de dados as chaves de NF-e pendentes de processamento dentro de um período.
    """
    logger.info(f"Buscando chaves pendentes no banco de dados via SQL para o período de {data_inicio} a {data_fim}...")

    if not sankhya_client:
        logger.error("Não foi possível buscar chaves pendentes: cliente Sankhya não inicializado.")
        return []

    try:
        # Query fornecida para buscar notas pendentes, agora com datas dinâmicas.
        sql = f"""
            SELECT DISTINCT
                CAB.CHAVENFE
            FROM TGFCAB CAB
            /* 
             O JOIN com TGFITE é necessário para garantir que estamos olhando apenas
             para notas que de fato possuem itens lançados.
            */
            INNER JOIN TGFITE ITE ON ITE.NUNOTA = CAB.NUNOTA
            WHERE CAB.DTNEG BETWEEN TO_DATE('{data_inicio}', 'DD/MM/YYYY') AND TO_DATE('{data_fim}', 'DD/MM/YYYY')
                AND CAB.CODEMP NOT IN (52, 53, 54, 55)
                AND CAB.CODTIPOPER NOT IN (206)
                AND CAB.CODTIPOPER = 1724
        """

        resposta = sankhya_client.execute_sql(sql=sql)
        linhas = normalizar_linhas_sankhya(resposta)

        if not linhas:
            logger.info("Nenhuma chave pendente encontrada no banco de dados para o período informado.")
            return []

        # Extrai a chave de cada linha, buscando pelo nome do campo 'CHAVE'.
        # Usa set() para garantir que cada chave seja processada apenas uma vez.
        chaves_pendentes = sorted(list(set([
            linha.get("CHAVENFE") for linha in linhas if linha and linha.get("CHAVENFE")
        ])))
        
        logger.info(f"Encontradas {len(chaves_pendentes)} chaves únicas para processamento em lote.")
        return chaves_pendentes

    except Exception as e:
        logger.error(f"Erro ao buscar chaves pendentes no banco: {e}", exc_info=True)
        return []

@app.route("/processar-lote", methods=["POST"])
def processar_lote():
    """Endpoint para processar um lote de NF-es pendentes do banco."""
    dados = request.get_json()
    if not dados or "data_inicio" not in dados or "data_fim" not in dados:
        return jsonify({"erro": "Parâmetros 'data_inicio' e 'data_fim' (DD/MM/YYYY) são obrigatórios."}), 400

    if not sankhya_client:
        return jsonify({"erro": "Erro crítico: Cliente Sankhya não está autenticado."}), 503

    chaves_pendentes = buscar_chaves_pendentes_no_banco(
        data_inicio=dados["data_inicio"],
        data_fim=dados["data_fim"]
    )
    
    if not chaves_pendentes:
        return jsonify({"status": "CONCLUIDO", "mensagem": "Nenhuma chave encontrada para o período."}), 200

    resultados = []
    
    for chave in chaves_pendentes:
        try:
            chave_limpa = limpar_chave_nfe(chave)
            resultado = processar_nfe(client=sankhya_client, chave_nfe=chave_limpa)
            resultados.append(resultado)
        except ValueError as e:
            resultados.append({"status": "ERRO_VALIDACAO", "chave_original": chave, "mensagem": str(e)})
        except Exception as e:
            logger.error(f"Erro inesperado ao processar a chave em lote '{chave}': {e}", exc_info=True)
            resultados.append({"status": "ERRO_TECNICO", "chave_original": chave, "mensagem": "Erro inesperado no servidor."})

    return jsonify(resultados)


@app.route("/exportar-lote", methods=["POST"])
def exportar_lote():
    """
    Recebe os resultados do processamento em lote (JSON) e gera um arquivo Excel.
    """
    resultados = request.get_json()
    if not resultados or not isinstance(resultados, list):
        return jsonify({"erro": "Nenhum dado válido para exportar."}), 400

    try:
        # Prepara os dados para o DataFrame, focando nas notas com divergência ou revisão
        dados_para_exportar = []
        for res in resultados:
            status = res.get("status", "ERRO")
            if status in ["DIVERGENTE", "REVISAO_MANUAL", "ERRO_VALIDACAO", "ERRO_TECNICO"]:
                dados_nota = res.get("dados", {})
                cabecalho = dados_nota.get("cabecalho", {})
                
                linha = {
                    "Status": status,
                    "Chave NF-e": dados_nota.get("chave_nfe", res.get("chave_original", "N/A")),
                    "Mensagem": res.get("mensagem", "Sem detalhes."),
                    "Fornecedor": cabecalho.get("NOMEPARC", "N/A"),
                    "Nro. Nota": cabecalho.get("NUMNOTA", "N/A"),
                    "Série": cabecalho.get("SERIENOTA", "N/A"),
                    "Valor Total": cabecalho.get("VLRNOTA", 0),
                    "Data Emissão": cabecalho.get("DTNEG", "N/A"),
                    "Nro. Único (Sankhya)": dados_nota.get("nunota", "N/A"),
                }
                dados_para_exportar.append(linha)

        if not dados_para_exportar:
             return jsonify({"erro": "Não há notas com divergências ou erros para exportar."}), 400

        # Cria o DataFrame e o arquivo Excel em memória
        df = pd.DataFrame(dados_para_exportar)
        buffer = io.BytesIO()
        df.to_excel(buffer, index=False, engine='openpyxl')
        buffer.seek(0)

        return send_file(
            buffer,
            as_attachment=True,
            download_name="relatorio_conferencia_nfe.xlsx",
            mimetype="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"
        )
    except Exception as e:
        logger.error(f"Erro ao gerar arquivo Excel: {e}", exc_info=True)
        return jsonify({"erro": f"Erro interno ao gerar o arquivo Excel: {e}"}), 500

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=True)