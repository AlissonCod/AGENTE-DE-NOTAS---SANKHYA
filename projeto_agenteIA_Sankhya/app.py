import logging
import os
import secrets
from datetime import datetime, timedelta
from functools import wraps
from urllib.parse import urlparse

from dotenv import load_dotenv
from flask import (
    Flask,
    jsonify,
    redirect,
    render_template,
    request,
    send_file,
    session,
    url_for,
)
import time
import traceback
import pandas as pd
import io

# Importa as funções de negócio do script principal
from main import (
    TOPS_ESPERADAS,
    autenticar_sankhya,
    limpar_chave_nfe,
    processar_nfe,
    normalizar_linhas_sankhya,
    corrigir_item_nfe,
)
from src import local_auth
from src.local_auth import TAMANHO_MINIMO_SENHA
from src.rules.icms import TABELA_DECISAO_CFOP_CST
from src.user_auth import (
    autenticar_usuario,
    grupos_autorizados,
    registrar_primeiro_acesso,
)

load_dotenv()

logger = logging.getLogger(__name__)

# ---------------------------------------------------------
# INICIALIZAÇÃO DO FLASK E CLIENTE SANKHYA
# ---------------------------------------------------------

app = Flask(__name__, template_folder='.')

# ---------------------------------------------------------
# SESSÃO DE USUÁRIO
# ---------------------------------------------------------
# A sessão é um cookie assinado com esta chave. Sem uma chave fixa no
# ambiente, geramos uma aleatória: a aplicação continua segura, mas todos os
# usuários caem no login a cada reinício do processo (e, com mais de um worker
# Gunicorn, a cada troca de worker). Por isso o aviso é em nível ERROR.
SECRET_KEY = (os.getenv("FLASK_SECRET_KEY") or "").strip()

if not SECRET_KEY:
    SECRET_KEY = secrets.token_hex(32)
    logger.error(
        "FLASK_SECRET_KEY ausente no ambiente. Uma chave temporária foi gerada e "
        "as sessões serão perdidas a cada reinício. Defina FLASK_SECRET_KEY no .env."
    )

app.secret_key = SECRET_KEY

# Duração do turno de trabalho: quem entra de manhã não é interrompido no meio
# da conferência de um lote.
DURACAO_SESSAO = timedelta(hours=8)

app.config.update(
    PERMANENT_SESSION_LIFETIME=DURACAO_SESSAO,
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Lax",
    # Em produção (HTTPS) o cookie deve ir apenas por conexão segura. Em
    # desenvolvimento local, sobre http, isso precisa ficar desligado.
    SESSION_COOKIE_SECURE=os.getenv("FLASK_COOKIE_SECURE", "false").strip().lower()
    in ("1", "true", "s", "sim", "yes"),
)

# Proteção simples contra tentativa de senha por força bruta. É por processo
# (não compartilhada entre workers do Gunicorn) e serve para desestimular o
# ataque trivial, não como controle definitivo.
MAX_TENTATIVAS_LOGIN = 5
BLOQUEIO_LOGIN = timedelta(minutes=5)
_tentativas_login = {}


def _chave_throttle() -> str:
    """Identifica quem está tentando logar, para efeito de bloqueio."""
    return request.remote_addr or "desconhecido"


def _login_bloqueado() -> int:
    """Retorna quantos segundos ainda faltam de bloqueio (0 se liberado)."""
    registro = _tentativas_login.get(_chave_throttle())

    if not registro:
        return 0

    tentativas, ultima = registro

    if tentativas < MAX_TENTATIVAS_LOGIN:
        return 0

    restante = (ultima + BLOQUEIO_LOGIN) - datetime.now()

    if restante.total_seconds() <= 0:
        _tentativas_login.pop(_chave_throttle(), None)
        return 0

    return int(restante.total_seconds())


def _registrar_falha_login() -> None:
    chave = _chave_throttle()
    tentativas, _ = _tentativas_login.get(chave, (0, datetime.now()))
    _tentativas_login[chave] = (tentativas + 1, datetime.now())


def _limpar_falhas_login() -> None:
    _tentativas_login.pop(_chave_throttle(), None)


def usuario_logado():
    """Devolve o usuário da sessão, ou None se não houver sessão válida.

    A expiração é conferida aqui pelo carimbo gravado no login, e não apenas
    pelo tempo de vida do cookie: o Flask renova a validade do cookie a cada
    requisição, o que transformaria as 8 horas em uma janela deslizante sem
    fim para quem mantém a aba aberta.
    """
    usuario = session.get("usuario")

    if not usuario:
        return None

    login_em = session.get("login_em")

    if not login_em:
        session.clear()
        return None

    try:
        momento_login = datetime.fromisoformat(login_em)
    except (TypeError, ValueError):
        session.clear()
        return None

    if datetime.now() - momento_login >= DURACAO_SESSAO:
        logger.info(
            "Sessão de '%s' expirada após %s.",
            usuario.get("nomeusu"),
            DURACAO_SESSAO,
        )
        session.clear()
        return None

    return usuario


def login_required(f):
    """Protege uma rota que serve HTML: manda quem não está logado ao login.

    Existem dois decorators em vez de um que tenta adivinhar pelo cabeçalho
    Accept: navegadores mandam '*/*;q=0.8' junto com 'text/html' até numa
    navegação comum, então qualquer heurística acaba classificando página como
    API (ou o contrário). Ser explícito na rota é mais confiável.
    """

    @wraps(f)
    def wrapper(*args, **kwargs):
        if usuario_logado():
            return f(*args, **kwargs)

        return redirect(url_for("login", proximo=request.full_path))

    return wrapper


def login_required_api(f):
    """Protege um endpoint JSON: devolve 401 para o fetch() tratar.

    O front-end tem um único ponto que observa o 401 (sessaoExpirada) e leva a
    pessoa para a tela de login, em vez de deixar a interface travada sem
    explicação depois que a sessão expira.
    """

    @wraps(f)
    def wrapper(*args, **kwargs):
        if usuario_logado():
            return f(*args, **kwargs)

        return jsonify({
            "status": "NAO_AUTENTICADO",
            "mensagem": "Sua sessão expirou. Faça login novamente.",
            "login_url": url_for("login"),
        }), 401

    return wrapper


def _destino_seguro(destino: str) -> str:
    """Valida o parâmetro 'proximo' antes de redirecionar.

    Sem isso, um link como /login?proximo=https://site-falso poderia usar a
    aplicação para jogar o usuário em outro domínio depois do login.
    """
    destino = (destino or "").strip()

    if not destino:
        return url_for("index")

    partes = urlparse(destino)

    if partes.scheme or partes.netloc or not destino.startswith("/"):
        return url_for("index")

    return destino

# --- INICIALIZAÇÃO ÚNICA DO CLIENTE SANKHYA ---
# O cliente é inicializado uma vez quando o processo do Flask/Gunicorn começa.
# Isso evita re-autenticações desnecessárias e resolve o problema do 405
# em health checks (GET) que acionavam a autenticação (POST).

VARIAVEIS_SANKHYA = (
    "SANKHYA_GATEWAY_URL",
    "SANKHYA_CLIENT_ID",
    "SANKHYA_CLIENT_SECRET",
    "SANKHYA_TOKEN",
)


def _diagnosticar_ambiente() -> str:
    """Aponta a causa provável de a aplicação não conseguir falar com o ERP.

    Sem isso, a falta de uma variável no .env chega ao usuário final como um
    genérico 'avise o suporte' na tela de login, e a causa real fica só numa
    linha de log que já rolou para fora da tela.
    """
    ausentes = [nome for nome in VARIAVEIS_SANKHYA if not (os.getenv(nome) or "").strip()]

    if not ausentes:
        return ""

    return (
        "Variável(is) de ambiente ausente(s): "
        + ", ".join(ausentes)
        + ". Copie projeto_agenteIA_Sankhya/.env.example para .env e preencha os valores."
    )


logger.info("Inicializando cliente Sankhya para a aplicação Flask...")

sankhya_client = autenticar_sankhya()

# Preenchido apenas quando há falha, para o log e para a tela de login em
# modo debug. O diagnóstico explica a falha; ele não decide se a autenticação
# é tentada — quem decide continua sendo o autenticar_sankhya() acima.
MOTIVO_SANKHYA_INDISPONIVEL = ""

if sankhya_client:
    logger.info("Cliente Sankhya autenticado e pronto para uso.")
else:
    MOTIVO_SANKHYA_INDISPONIVEL = _diagnosticar_ambiente() or (
        "As variáveis estão presentes, mas o Gateway recusou a autenticação ou "
        "está inacessível. Confira os valores e a conectividade de rede."
    )

    logger.error(
        "\n"
        "============================================================\n"
        " FALHA CRITICA: a aplicacao NAO conseguiu autenticar no Sankhya.\n"
        " Enquanto isso, ninguem consegue entrar no EucaVerify.\n"
        "\n"
        " Causa provavel: %s\n"
        "============================================================",
        MOTIVO_SANKHYA_INDISPONIVEL,
    )

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

def _iniciar_sessao(usuario: dict) -> None:
    """Grava a sessão do usuário recém-autenticado.

    O session.clear() antes de gravar evita que resíduo de uma sessão
    anterior (fixação de sessão) sobreviva ao login.
    """
    session.clear()
    session.permanent = True
    session["usuario"] = usuario
    session["login_em"] = datetime.now().isoformat(timespec="seconds")

    # Quem nunca viu o passo a passo recebe o convite assim que a tela
    # principal abre. A consulta é feita aqui, uma vez por login, para que o
    # carregamento da página não dependa de mais uma ida ao banco.
    try:
        session["tour_pendente"] = local_auth.tour_pendente(usuario.get("nomeusu", ""))
    except Exception as e:
        logger.error("Falha ao verificar o passo a passo do usuário: %s", e)
        session["tour_pendente"] = False


@app.route("/login", methods=["GET", "POST"])
def login():
    """Autentica o usuário do EucaVerify.

    Quem pode entrar vem da TSIUSU (usuário existente, acesso vigente e grupo
    autorizado); a senha é a do EucaVerify, criada no primeiro acesso. A
    sessão guarda apenas o NOMEUSU, o CODUSU e o grupo de quem entrou.
    """
    proximo = request.values.get("proximo", "")

    if request.method == "GET":
        if usuario_logado():
            return redirect(_destino_seguro(proximo))

        return render_template("login.html", erro=None, usuario="", proximo=proximo)

    usuario_informado = (request.form.get("usuario") or "").strip()

    def render_erro(mensagem: str, status_http: int = 401):
        return (
            render_template(
                "login.html",
                erro=mensagem,
                usuario=usuario_informado,
                proximo=proximo,
            ),
            status_http,
        )

    segundos_bloqueio = _login_bloqueado()

    if segundos_bloqueio:
        minutos = max(1, round(segundos_bloqueio / 60))
        logger.warning("Login bloqueado por tentativas excessivas (%s).", _chave_throttle())
        return render_erro(
            f"Muitas tentativas de login. Aguarde {minutos} minuto(s) e tente novamente.",
            429,
        )

    if not sankhya_client:
        logger.error(
            "Tentativa de login com cliente Sankhya não autenticado. Causa: %s",
            MOTIVO_SANKHYA_INDISPONIVEL or "desconhecida",
        )

        mensagem = "O sistema não conseguiu se conectar ao Sankhya. Avise o suporte."

        # Em desenvolvimento, mostra a causa na própria tela: é quase sempre
        # configuração faltando, e ficar caçando no log atrasa à toa. Em
        # produção a mensagem continua genérica, sem expor detalhes internos.
        if app.debug and MOTIVO_SANKHYA_INDISPONIVEL:
            mensagem = f"{mensagem} [modo debug] {MOTIVO_SANKHYA_INDISPONIVEL}"

        return render_erro(mensagem, 503)

    try:
        resultado = autenticar_usuario(
            client=sankhya_client,
            identificador=usuario_informado,
            senha=request.form.get("senha") or "",
        )
    except Exception as e:
        logger.error("Erro inesperado ao autenticar usuário: %s", e, exc_info=True)
        return render_erro("Erro inesperado ao validar o login. Tente novamente.", 500)

    # Quem ainda não criou senha é mandado para o primeiro acesso, com o
    # usuário já preenchido. Isso não conta como tentativa de senha errada.
    if resultado["status"] == "PRIMEIRO_ACESSO":
        return redirect(
            url_for("primeiro_acesso", usuario=usuario_informado, proximo=proximo)
        )

    if resultado["status"] != "APROVADO":
        _registrar_falha_login()

        status_http = 503 if resultado["status"] == "ERRO_TECNICO" else 401

        return render_erro(resultado["mensagem"], status_http)

    _limpar_falhas_login()
    _iniciar_sessao(resultado["usuario"])

    logger.info("Usuário '%s' entrou no EucaVerify.", resultado["usuario"]["nomeusu"])

    return redirect(_destino_seguro(proximo))


@app.route("/primeiro-acesso", methods=["GET", "POST"])
def primeiro_acesso():
    """Cria a senha do EucaVerify na primeira vez que a pessoa entra.

    Exige confirmar o e-mail que está cadastrado nela na TSIUSU: sem isso,
    conhecer o nome de usuário de um colega bastaria para criar a senha dele
    e assinar correções em seu nome.
    """
    proximo = request.values.get("proximo", "")
    usuario_informado = (request.values.get("usuario") or "").strip()
    email_informado = (request.form.get("email") or "").strip()

    def render_tela(erro=None, status_http=200):
        return (
            render_template(
                "primeiro_acesso.html",
                erro=erro,
                usuario=usuario_informado,
                email=email_informado,
                proximo=proximo,
                tamanho_minimo=TAMANHO_MINIMO_SENHA,
            ),
            status_http,
        )

    if request.method == "GET":
        return render_tela()

    segundos_bloqueio = _login_bloqueado()

    if segundos_bloqueio:
        minutos = max(1, round(segundos_bloqueio / 60))
        return render_tela(
            f"Muitas tentativas. Aguarde {minutos} minuto(s) e tente novamente.", 429
        )

    if not sankhya_client:
        return render_tela(
            "O sistema não conseguiu se conectar ao Sankhya. Avise o suporte.", 503
        )

    try:
        resultado = registrar_primeiro_acesso(
            client=sankhya_client,
            identificador=usuario_informado,
            email=email_informado,
            senha=request.form.get("senha") or "",
            confirmacao=request.form.get("confirmacao") or "",
        )
    except Exception as e:
        logger.error("Erro inesperado no primeiro acesso: %s", e, exc_info=True)
        return render_tela("Erro inesperado. Tente novamente.", 500)

    if resultado["status"] != "APROVADO":
        # Só conta como tentativa suspeita quando o e-mail não confere; erro
        # de digitação na senha nova não deve bloquear a pessoa.
        if "e-mail" in resultado["mensagem"].lower():
            _registrar_falha_login()

        status_http = 503 if resultado["status"] == "ERRO_TECNICO" else 400

        return render_tela(resultado["mensagem"], status_http)

    _limpar_falhas_login()
    _iniciar_sessao(resultado["usuario"])

    logger.info(
        "Usuário '%s' criou a senha e entrou no EucaVerify.",
        resultado["usuario"]["nomeusu"],
    )

    return redirect(_destino_seguro(proximo))


@app.route("/logout", methods=["GET", "POST"])
def logout():
    """Encerra a sessão local do usuário."""
    usuario = session.get("usuario") or {}

    if usuario:
        logger.info("Usuário '%s' saiu do EucaVerify.", usuario.get("nomeusu"))

    session.clear()

    return redirect(url_for("login"))


@app.route("/sessao", methods=["GET"])
def sessao():
    """Informa ao front-end quem está logado, para exibir no cabeçalho."""
    usuario = usuario_logado()

    if not usuario:
        return jsonify({"autenticado": False}), 401

    return jsonify(
        {
            "autenticado": True,
            "usuario": usuario,
            "tour_pendente": bool(session.get("tour_pendente")),
        }
    )


@app.route("/")
@login_required
def index():
    """Renderiza a página HTML principal da interface."""
    return render_template(
        "index.html", tour_pendente=bool(session.get("tour_pendente"))
    )


@app.route("/tour/concluir", methods=["POST"])
@login_required_api
def tour_concluir():
    """Registra que a pessoa já viu o passo a passo e não precisa revê-lo.

    Chamada tanto quando ela chega ao fim quanto quando dispensa o convite:
    nos dois casos ela já foi apresentada à plataforma, e insistir seria só
    atrapalhar. O passo a passo continua disponível pelo botão do cabeçalho.
    """
    usuario = usuario_logado() or {}

    session["tour_pendente"] = False

    try:
        local_auth.marcar_tour_concluido(usuario.get("nomeusu", ""))
    except Exception as e:
        # A sessão atual já não mostra mais o convite; só a memória entre
        # sessões se perde, o que não justifica devolver erro para a tela.
        logger.error("Falha ao registrar a conclusão do passo a passo: %s", e)

    return jsonify({"ok": True})


@app.route("/validar", methods=["POST"])
@login_required_api
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


@app.route("/regras-icms", methods=["GET"])
@login_required_api
def regras_icms():
    """Expõe a tabela de CFOP -> CSTs permitidos, usada pelo front-end para
    montar os dropdowns de correção sem duplicar a regra de negócio."""
    return jsonify(TABELA_DECISAO_CFOP_CST)


@app.route("/corrigir-item", methods=["POST"])
@login_required_api
def corrigir_item():
    """Recebe uma correção de CFOP/CST de um item da NF-e feita no front-end,
    revalida contra as regras fiscais e, se aprovada, grava o UPDATE no Sankhya."""
    dados = request.get_json(silent=True) or {}

    campos_obrigatorios = ["nunota", "sequencia", "cfop_novo", "cst_novo"]
    faltando = [campo for campo in campos_obrigatorios if not dados.get(campo)]

    if faltando:
        return jsonify({
            "erro": f"Campo(s) obrigatório(s) ausente(s): {', '.join(faltando)}."
        }), 400

    if not sankhya_client:
        return jsonify({"erro": "Erro crítico: Cliente Sankhya não está autenticado."}), 503

    # O responsável pela correção vem SEMPRE da sessão autenticada, nunca do
    # corpo da requisição. É o que garante que a trilha de auditoria em
    # logs/correcoes_auditoria.jsonl aponte para quem realmente assinou a
    # alteração: ninguém consegue registrar uma correção no nome de outro.
    usuario = usuario_logado() or {}
    responsavel = usuario.get("nomeusu", "")

    if not responsavel:
        return jsonify({
            "status": "NAO_AUTENTICADO",
            "mensagem": "Sua sessão expirou. Faça login novamente.",
        }), 401

    try:
        resultado = corrigir_item_nfe(
            client=sankhya_client,
            chave_nfe=dados.get("chave_nfe", ""),
            nunota=dados["nunota"],
            sequencia=dados["sequencia"],
            cfop_atual=dados.get("cfop_atual", ""),
            cst_atual=dados.get("cst_atual", ""),
            cfop_novo=dados["cfop_novo"],
            cst_novo=dados["cst_novo"],
            uf_origem=dados.get("uf_origem", ""),
            responsavel=responsavel,
        )
        return jsonify(resultado)
    except ValueError as e:
        return jsonify({"status": "ERRO_VALIDACAO", "mensagem": str(e)}), 400
    except Exception as e:
        logger.error(f"Erro inesperado ao corrigir item: {e}", exc_info=True)
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
        # As TOPs vêm da constante de main.py (valores internos, não entrada do
        # usuário), então a interpolação aqui é segura. Basta incluir uma nova
        # TOP em TOPS_ESPERADAS para que o lote passe a varrê-la também.
        tops_no_escopo = ", ".join(TOPS_ESPERADAS)

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
                AND CAB.CODTIPOPER NOT IN (206) --- só pra garantir
                AND CAB.CODTIPOPER IN ({tops_no_escopo})
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
@login_required_api
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
@login_required_api
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
                    "Data Emissão": cabecalho.get("DTNEG", "N/A"), # Corrigido para usar DTNEG
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