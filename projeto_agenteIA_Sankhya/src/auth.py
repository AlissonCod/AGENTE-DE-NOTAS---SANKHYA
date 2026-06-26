import logging
import os
import time
from typing import Dict, Optional

import requests
from dotenv import load_dotenv

load_dotenv()

logger = logging.getLogger(__name__)


class AuthManager:
    """
    Gerenciador de autenticação para integração com o ERP Sankhya.
    Centraliza as credenciais e gerencia o Bearer Token dinâmico.
    """

    def __init__(self) -> None:
        self.gateway_url = self._get_env("SANKHYA_GATEWAY_URL")
        self.client_id = self._get_env("SANKHYA_CLIENT_ID")
        self.client_secret = self._get_env("SANKHYA_CLIENT_SECRET")

        # Este é o X-Token fixo gerado no Sankhya.
        # Não é o Bearer Token.
        self.token = self._get_env("SANKHYA_TOKEN")

        # Este é o Bearer JWT dinâmico retornado pelo /authenticate.
        self.access_token: Optional[str] = None

        # Controle simples de validade em memória.
        self.token_created_at: Optional[float] = None
        self.expires_in: Optional[int] = None

        self._validate_env_vars()

    def _get_env(self, name: str) -> Optional[str]:
        """
        Lê variável de ambiente removendo espaços acidentais.
        """
        value = os.getenv(name)

        if value is not None:
            value = value.strip()

        return value

    def _validate_env_vars(self) -> None:
        """
        Valida se as variáveis essenciais foram carregadas.
        """
        if not self.gateway_url:
            raise ValueError("SANKHYA_GATEWAY_URL ausente no ambiente.")

        if not self.client_id:
            raise ValueError("SANKHYA_CLIENT_ID ausente no ambiente.")

        if not self.client_secret:
            raise ValueError("SANKHYA_CLIENT_SECRET ausente no ambiente.")

        if not self.token:
            raise ValueError("SANKHYA_TOKEN ausente no ambiente.")

    def authenticate(self, force: bool = False) -> bool:
        """
        Realiza autenticação no Gateway Sankhya e obtém um novo Bearer Token.

        :param force: quando True, força a renovação mesmo se já existir token.
        :return: True se autenticou com sucesso, False caso contrário.
        """
        if self.access_token and not force and not self.is_token_expired():
            return True

        base_domain = self.gateway_url.split("/gateway")[0].rstrip("/")
        auth_url = f"{base_domain}/authenticate"

        payload = {
            "grant_type": "client_credentials",
            "client_id": self.client_id,
            "client_secret": self.client_secret,
        }

        headers = {
            "Content-Type": "application/x-www-form-urlencoded",
            "X-Token": self.token,
        }

        try:
            logger.info("Autenticando no Gateway Sankhya...")

            response = requests.post(
                auth_url,
                data=payload,
                headers=headers,
                timeout=(10, 60),
            )

            response.raise_for_status()

            data = response.json()

            access_token = data.get("access_token")

            if not access_token:
                logger.error("Resposta de autenticação sem access_token: %s", data)
                return False

            self.access_token = access_token
            self.token_created_at = time.time()

            # Caso a API retorne expires_in, usamos.
            # Caso não retorne, deixamos None e renovamos apenas quando houver 403 GTW3403.
            expires_in = data.get("expires_in")

            try:
                self.expires_in = int(expires_in) if expires_in else None
            except (TypeError, ValueError):
                self.expires_in = None

            logger.info("Bearer Token Sankhya obtido com sucesso.")

            return True

        except requests.exceptions.Timeout as e:
            logger.error("Timeout ao autenticar na API Sankhya: %s", e)
            return False

        except requests.exceptions.RequestException as e:
            logger.error("Erro na autenticação da API Sankhya: %s", e)

            if getattr(e, "response", None) is not None:
                logger.error("Detalhes da autenticação Sankhya: %s", e.response.text)

            return False

        except Exception as e:
            logger.exception("Erro inesperado ao autenticar na API Sankhya: %s", e)
            return False

    def is_token_expired(self) -> bool:
        """
        Verifica se o token expirou com base no expires_in, quando disponível.
        """
        if not self.access_token:
            return True

        if not self.token_created_at or not self.expires_in:
            return False

        margem_segundos = 60
        idade_token = time.time() - self.token_created_at

        return idade_token >= (self.expires_in - margem_segundos)

    def get_headers(self) -> Dict[str, str]:
        """
        Gera os cabeçalhos HTTP padrão para consumo dos endpoints do Gateway.
        """
        if not self.access_token or self.is_token_expired():
            self.authenticate(force=True)

        headers = {
            "Content-Type": "application/json",
            "Accept": "application/json",
            "X-Token": self.token,
        }

        if self.access_token:
            headers["Authorization"] = f"Bearer {self.access_token}"

        return headers

    def force_refresh_token(self) -> bool:
        """
        Força renovação do Bearer Token.
        Use quando a Sankhya retornar GTW3403.
        """
        self.access_token = None
        self.token_created_at = None
        self.expires_in = None

        return self.authenticate(force=True)