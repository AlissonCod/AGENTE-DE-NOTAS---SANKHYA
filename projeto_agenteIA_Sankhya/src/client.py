import logging
import requests
from typing import Any, Dict, List, Optional

from src.auth import AuthManager

logger = logging.getLogger(__name__)

class SankhyaClient:
    """
    Cliente HTTP genérico para comunicação com os serviços (mge/service.sbr) do ERP Sankhya.
    """
    
    def __init__(self) -> None:
        self.auth = AuthManager()
        self.session = requests.Session()
        
        # No início do fluxo, chama a autenticação do AuthManager
        if not self.auth.authenticate():
            logger.error("Falha ao obter o Bearer Token do Gateway Sankhya.")
            raise ValueError("Erro Crítico de Autenticação: Não foi possível obter o token.")

    def load_records(
        self,
        entity_name: str,
        criteria: Optional[Dict[str, Any]] = None,
        result_fields: Optional[List[str]] = None,
    ) -> Dict[str, Any]:
        """
        Realiza uma consulta genérica no Sankhya usando CRUDServiceProvider.loadRecords.
        
        :param entity_name: Nome da entidade raiz (Ex: 'CabecalhoNota', 'ItemNota', 'TGFCAB')
        :param criteria: Filtros SQL encapsulados do Sankhya
        :param result_fields: Lista de campos que devem ser retornados na consulta.
        :return: Dicionário contendo o JSON de resposta com os registros.
        """
        url = f"{self.auth.gateway_url}/mge/service.sbr?serviceName=CRUDServiceProvider.loadRecords&outputType=json"
        
        headers = self.auth.get_headers()

        payload = {
            "serviceName": "CRUDServiceProvider.loadRecords",
            "requestBody": {
                "dataSet": {
                    "rootEntity": entity_name,
                    "includePresentationFields": "S",
                    "offsetPage": "0",
                    "criteria": criteria or {},
                },
            }
        }

        if result_fields:
            payload["requestBody"]["dataSet"]["resultFields"] = {
                "resultField": [{"$": field} for field in result_fields]
            }

        try:
            response = self.session.post(url, json=payload, headers=headers, timeout=90)
            response.raise_for_status()
            
            data = response.json()
            
            if str(data.get("status", "")) != "1":
                raise ValueError(f"Resposta bruta do ERP: {data}")
                
            return data
            
        except requests.exceptions.HTTPError as http_err:
            raise ValueError(f"Erro HTTP do Gateway: Status {http_err.response.status_code} - Corpo: {http_err.response.text}")
        except requests.exceptions.RequestException as req_err:
            raise ValueError(f"Falha de conectividade ao acessar {entity_name}: {req_err}")

    def execute_sql(self, sql: str) -> Dict[str, Any]:
        """
        Plano B: Executa uma consulta SQL direta no banco de dados via DbExplorerSP.
        
        :param sql: String contendo a query (Ex: 'SELECT * FROM TGFCAB')
        """
        url = f"{self.auth.gateway_url}/mge/service.sbr?serviceName=DbExplorerSP.executeQuery&outputType=json"
        
        headers = self.auth.get_headers()
        
        payload = {
            "serviceName": "DbExplorerSP.executeQuery",
            "requestBody": {
                "sql": sql
            }
        }

        try:
            response = self.session.post(url, json=payload, headers=headers, timeout=90)
            response.raise_for_status()
            
            data = response.json()
            if str(data.get("status", "")) != "1":
                raise ValueError(f"Resposta bruta do ERP: {data}")
                
            return data
        except requests.exceptions.HTTPError as http_err:
            raise ValueError(f"Erro HTTP do Gateway: Status {http_err.response.status_code} - Corpo: {http_err.response.text}")
        except requests.exceptions.RequestException as req_err:
            raise ValueError(f"Falha de rede ao executar SQL: {req_err}")
