"""
Administração dos acessos ao EucaVerify.

Use quando alguém esquecer a senha (liberar novo primeiro acesso), para ver
quem já criou senha ou para conferir quem está autorizado no Sankhya.

    python gerenciar_usuarios.py listar
    python gerenciar_usuarios.py autorizados
    python gerenciar_usuarios.py liberar ALISSON.JUNIOR
    python gerenciar_usuarios.py definir-senha ALISSON.JUNIOR

A senha, quando definida por aqui, é pedida sem eco no terminal e nunca
aparece no histórico do shell.
"""

import argparse
import getpass
import logging
import sys

from dotenv import load_dotenv

load_dotenv()

logging.basicConfig(level=logging.WARNING, format="%(levelname)s - %(message)s")


def _cliente():
    from main import autenticar_sankhya

    client = autenticar_sankhya()

    if client is None:
        print("ERRO: não foi possível autenticar no Sankhya. Confira o .env.")
        sys.exit(1)

    return client


def _mostrar_armazenamento() -> None:
    """Diz em qual banco este comando está mexendo.

    Rodar o script sem EUCAVERIFY_DATABASE_URL no ambiente administra o SQLite
    local, não a produção. Imprimir a origem evita liberar a senha de alguém no
    banco errado e achar que não funcionou.
    """
    from src import local_auth

    print(f"Banco de senhas: {local_auth.descricao_armazenamento()}\n")


def comando_listar() -> None:
    """Mostra quem já criou senha no EucaVerify."""
    from src import local_auth

    _mostrar_armazenamento()

    usuarios = local_auth.listar_usuarios()

    if not usuarios:
        print("Nenhum usuário criou senha ainda.")
        return

    print(f"{len(usuarios)} usuário(s) com senha criada:\n")
    print(f"  {'USUÁRIO':26} {'CRIADA EM':20} {'ÚLTIMO ACESSO':20}")
    print(f"  {'-' * 26} {'-' * 20} {'-' * 20}")

    for u in usuarios:
        print(
            f"  {u['nomeusu'][:26]:26} {(u['criado_em'] or '-')[:19]:20} "
            f"{(u['ultimo_acesso'] or 'nunca')[:19]:20}"
        )


def comando_autorizados() -> None:
    """Lista quem o Sankhya autoriza a usar o EucaVerify."""
    from main import normalizar_linhas_sankhya
    from src import local_auth
    from src.user_auth import grupos_autorizados

    _mostrar_armazenamento()

    client = _cliente()
    grupos = ", ".join(str(g) for g in grupos_autorizados())

    sql = f"""
        SELECT USU.CODUSU, USU.NOMEUSU, USU.EMAIL, GRU.NOMEGRUPO
        FROM TSIUSU USU
        LEFT JOIN TSIGRU GRU ON GRU.CODGRUPO = USU.CODGRUPO
        WHERE USU.CODGRUPO IN ({grupos})
          AND (USU.DTLIMACESSO IS NULL OR USU.DTLIMACESSO >= TRUNC(SYSDATE))
        ORDER BY GRU.NOMEGRUPO, USU.NOMEUSU
    """

    linhas = normalizar_linhas_sankhya(client.execute_sql(sql=sql))

    print(f"Grupos autorizados (CODGRUPO): {grupos}")
    print(f"{len(linhas)} usuário(s) com acesso vigente:\n")
    print(f"  {'USUÁRIO':26} {'GRUPO':20} {'E-MAIL':34} SENHA")
    print(f"  {'-' * 26} {'-' * 20} {'-' * 34} {'-' * 12}")

    for l in linhas:
        nome = str(l.get("NOMEUSU") or "").strip()
        email = str(l.get("EMAIL") or "").strip()
        grupo = str(l.get("NOMEGRUPO") or "").strip()

        if not email:
            situacao = "SEM E-MAIL"
        elif local_auth.tem_senha(nome):
            situacao = "criada"
        else:
            situacao = "pendente"

        print(f"  {nome[:26]:26} {grupo[:20]:20} {(email or '-')[:34]:34} {situacao}")

    sem_email = [l for l in linhas if not str(l.get("EMAIL") or "").strip()]

    if sem_email:
        print(
            f"\nAtenção: {len(sem_email)} usuário(s) sem e-mail na TSIUSU não "
            "conseguem fazer o primeiro acesso sozinhos."
        )
        print("Cadastre o e-mail no Sankhya, ou use: definir-senha <USUARIO>")


def comando_liberar(nomeusu: str) -> None:
    """Apaga a senha para a pessoa refazer o primeiro acesso."""
    from src import local_auth

    _mostrar_armazenamento()

    if local_auth.remover_usuario(nomeusu):
        print(f"Senha de '{nomeusu}' removida.")
        print("A pessoa pode criar outra em /primeiro-acesso, confirmando o e-mail.")
    else:
        print(f"'{nomeusu}' não tinha senha criada. Nada a fazer.")


def comando_definir_senha(nomeusu: str) -> None:
    """Define a senha manualmente, para quem não tem e-mail na TSIUSU."""
    from src import local_auth
    from src.user_auth import buscar_usuario_autorizado

    _mostrar_armazenamento()

    client = _cliente()
    linha = buscar_usuario_autorizado(client, nomeusu)

    if not linha:
        print(
            f"'{nomeusu}' não existe, está com acesso expirado, ou não pertence "
            "a um grupo autorizado. Confira com: autorizados"
        )
        sys.exit(1)

    nome_real = str(linha.get("NOMEUSU") or nomeusu).strip()

    if local_auth.tem_senha(nome_real):
        resposta = input(f"'{nome_real}' já tem senha. Substituir? (s/N) ").strip().lower()

        if resposta != "s":
            print("Cancelado.")
            return

    senha = getpass.getpass(f"Nova senha para '{nome_real}': ")
    confirmacao = getpass.getpass("Repita a senha: ")

    erro = local_auth.validar_forca_senha(senha, confirmacao)

    if erro:
        print(f"ERRO: {erro}")
        sys.exit(1)

    local_auth.definir_senha(
        nomeusu=nome_real, senha=senha, codusu=linha.get("CODUSU")
    )

    print(f"Senha definida para '{nome_real}'. Entregue-a à pessoa com segurança.")


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Administração dos acessos ao EucaVerify."
    )
    sub = parser.add_subparsers(dest="comando", required=True)

    sub.add_parser("listar", help="Quem já criou senha no EucaVerify.")
    sub.add_parser("autorizados", help="Quem o Sankhya autoriza, e o estado de cada um.")

    p = sub.add_parser("liberar", help="Apaga a senha para refazer o primeiro acesso.")
    p.add_argument("nomeusu")

    p = sub.add_parser("definir-senha", help="Define a senha manualmente.")
    p.add_argument("nomeusu")

    args = parser.parse_args()

    if args.comando == "listar":
        comando_listar()
    elif args.comando == "autorizados":
        comando_autorizados()
    elif args.comando == "liberar":
        comando_liberar(args.nomeusu)
    elif args.comando == "definir-senha":
        comando_definir_senha(args.nomeusu)


if __name__ == "__main__":
    main()
