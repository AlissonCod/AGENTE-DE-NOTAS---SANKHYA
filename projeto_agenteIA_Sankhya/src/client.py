import logging
import requests
from typing import Any, Dict, List, Optional

from src.auth import AuthManager

logger = logging.getLogger(__name__)


class SankhyaClient:
    """
    Cliente HTTP genérico para comunicação com os serviços (mge/service.sbr) do ERP Sankhya.
    Com renovação automática do Bearer Token quando expirar.
    """

    def __init__(self) -> None:
        self.auth = AuthManager()
        self.session = requests.Session()

        if not self.auth.authenticate():
            logger.error("Falha ao obter o Bearer Token do Gateway Sankhya.")
            raise ValueError("Erro Crítico de Autenticação: Não foi possível obter o token.")

    def _token_expirado_ou_invalido(self, response: requests.Response) -> bool:
        """
        Verifica se a resposta da Sankhya indica token expirado/inválido.
        """
        if response.status_code != 403:
            return False

        texto = response.text or ""

        return (
            "GTW3403" in texto
            or "Bearer Token inválido" in texto
            or "Bearer Token invalido" in texto
            or "Expirado" in texto
        )

    def _post_service(
        self,
        service_name: str,
        payload: Dict[str, Any],
        timeout: int = 90,
        retry_auth: bool = True,
    ) -> Dict[str, Any]:
        """
        Executa um POST genérico para o Gateway Sankhya.
        Se o token estiver expirado, renova e tenta mais uma vez.
        """
        url = (
            f"{self.auth.gateway_url}/mge/service.sbr"
            f"?serviceName={service_name}&outputType=json"
        )

        headers = self.auth.get_headers()

        try:
            logger.info("Chamando serviço Sankhya: %s", service_name)

            response = self.session.post(
                url,
                json=payload,
                headers=headers,
                timeout=timeout,
            )

            if self._token_expirado_ou_invalido(response) and retry_auth:
                logger.warning(
                    "Bearer Token Sankhya expirado/inválido ao chamar %s. Renovando token...",
                    service_name,
                )

                if not self.auth.force_refresh_token():
                    raise ValueError(
                        "Erro de autenticação: não foi possível renovar o Bearer Token Sankhya."
                    )

                headers = self.auth.get_headers()

                logger.info("Token renovado. Tentando novamente o serviço: %s", service_name)

                response = self.session.post(
                    url,
                    json=payload,
                    headers=headers,
                    timeout=timeout,
                )

            response.raise_for_status()

            data = response.json()

            if str(data.get("status", "")) != "1":
                raise ValueError(f"Resposta bruta do ERP: {data}")

            return data

        except requests.exceptions.HTTPError as http_err:
            status_code = (
                http_err.response.status_code
                if http_err.response is not None
                else "SEM_STATUS"
            )

            corpo = (
                http_err.response.text
                if http_err.response is not None
                else "SEM_CORPO"
            )

            raise ValueError(
                f"Erro HTTP do Gateway: Status {status_code} - Corpo: {corpo}"
            )

        except requests.exceptions.Timeout as timeout_err:
            raise ValueError(
                f"Timeout ao chamar serviço Sankhya {service_name}: {timeout_err}"
            )

        except requests.exceptions.RequestException as req_err:
            raise ValueError(
                f"Falha de conectividade ao chamar serviço Sankhya {service_name}: {req_err}"
            )

        except ValueError:
            raise

        except Exception as e:
            logger.exception("Erro inesperado ao chamar serviço Sankhya %s", service_name)
            raise ValueError(
                f"Erro inesperado ao chamar serviço Sankhya {service_name}: {e}"
            )

    def load_records(
        self,
        entity_name: str,
        criteria: Optional[Dict[str, Any]] = None,
        result_fields: Optional[List[str]] = None,
    ) -> Dict[str, Any]:
        """
        Realiza uma consulta genérica no Sankhya usando CRUDServiceProvider.loadRecords.
        """
        service_name = "CRUDServiceProvider.loadRecords"

        payload = {
            "serviceName": service_name,
            "requestBody": {
                "dataSet": {
                    "rootEntity": entity_name,
                    "includePresentationFields": "S",
                    "offsetPage": "0",
                    "criteria": criteria or {},
                }
            },
        }

        if result_fields:
            payload["requestBody"]["dataSet"]["resultFields"] = {
                "resultField": [{"$": field} for field in result_fields]
            }

        return self._post_service(
            service_name=service_name,
            payload=payload,
            timeout=90,
        )

    def execute_sql(self, sql: str) -> Dict[str, Any]:
        """
        Executa uma consulta SQL direta no banco de dados via DbExplorerSP.
        """
        service_name = "DbExplorerSP.executeQuery"

        payload = {
            "serviceName": service_name,
            "requestBody": {
                "sql": sql
            },
        }

        return self._post_service(
            service_name=service_name,
            payload=payload,
            timeout=90,
        )