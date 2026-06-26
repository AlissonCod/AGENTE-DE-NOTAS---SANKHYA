import logging
from flask import Flask, jsonify, render_template, request, send_file
import time
import traceback
import pandas as pd
import io

# Importa as funções de negócio do script principal
from main import autenticar_sankhya, limpar_chave_nfe, processar_nfe, normalizar_linhas_sankhya

logger = logging.getLogger(__name__)

# ---------------------------------------------------------
# INICIALIZAÇÃO DO FLASK E CLIENTE SANKHYA
# ---------------------------------------------------------

app = Flask(__name__, template_folder='.')

# --- INICIALIZAÇÃO ÚNICA DO CLIENTE SANKHYA ---
# O cliente é inicializado uma vez quando o processo do Flask/Gunicorn começa.
# Isso evita re-autenticações desnecessárias e resolve o problema do 405
# em health checks (GET) que acionavam a autenticação (POST).
logger.info("Inicializando cliente Sankhya para a aplicação Flask...")
sankhya_client = autenticar_sankhya()
if sankhya_client:
    logger.info("Cliente Sankhya autenticado e pronto para uso.")
else:
    logger.error("FALHA CRÍTICA: Não foi possível autenticar o cliente Sankhya na inicialização.")

# ---------------------------------------------------------
# LOGS E HANDLERS DE ERRO
# ---------------------------------------------------------

@app.before_request
def log_request_info():
    """Log detalhado para cada requisição recebida."""
    logger.info(
        "REQ method=%s path=%s url=%s origin=%s content_type=%s",
        request.method,
        request.path,
        request.url,
        request.headers.get("Origin"),
        request.headers.get("Content-Type")
    )

@app.errorhandler(405)
def erro_405(e):
    """Handler específico para erros de 'Método Não Permitido'."""
    valid_methods = getattr(e, "valid_methods", None)
    logger.error(
        "405 Method Not Allowed | method=%s | path=%s | allowed=%s",
        request.method, request.path, valid_methods
    )
    return jsonify({
        "status": "ERRO_405", "mensagem": "Método HTTP não permitido para esta rota.",
        "rota": request.path, "metodo_recebido": request.method, "metodos_permitidos": valid_methods
    }), 405

@app.errorhandler(Exception)
def handle_exception(e):
    """
    Manipulador de erro global. Captura qualquer exceção não tratada
    e a retorna em formato JSON padronizado, evitando respostas em HTML.
    """
    # Para um log mais detalhado do erro no servidor
    logger.error(f"Erro não tratado na aplicação: {e}", exc_info=True)
    return jsonify({"status": "ERRO_FATAL_SERVIDOR", "mensagem": f"Ocorreu um erro inesperado no servidor: {e}"}), 500

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
    try:
        logger.info("=== INICIO /processar-lote ===")
        logger.info("BODY RAW: %s", request.get_data(as_text=True))

        dados = request.get_json(silent=True)
        logger.info("JSON RECEBIDO: %s", dados)

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

        logger.info("=== FIM /processar-lote ===")
        return jsonify(resultados)

    except Exception as e:
        logger.error("=== ERRO FATAL EM /processar-lote ===")
        logger.error("TIPO ERRO: %s", type(e).__name__)
        logger.error("ERRO: %s", str(e))
        logger.error(traceback.format_exc())
        return jsonify({"status": "ERRO_FATAL_SERVIDOR", "mensagem": str(e), "tipo_erro": type(e).__name__}), 500


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
    app.run(host="0.0.0.0", port=5002, debug=True)