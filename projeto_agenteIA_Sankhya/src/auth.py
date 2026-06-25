import os
import requests
from typing import Dict, Optional
from dotenv import load_dotenv

# Carrega as variáveis de ambiente em tempo de execução
load_dotenv()

class AuthManager:
    """
    Gerenciador de autenticação para integração com o ERP Sankhya.
    Centraliza a leitura das configurações sensíveis e gerencia o ciclo de vida do token JWT.
    """
    
    def __init__(self) -> None:
        self.gateway_url = os.getenv("SANKHYA_GATEWAY_URL")
        self.client_id = os.getenv("SANKHYA_CLIENT_ID")
        self.client_secret = os.getenv("SANKHYA_CLIENT_SECRET")
        self.token = os.getenv("SANKHYA_TOKEN") # Este é o X-Token (Fixo)
        
        self.access_token: Optional[str] = None # Este será o Bearer JWT (Dinâmico)
        
        self._validate_env_vars()

    def _validate_env_vars(self) -> None:
        """Valida se as variáveis essenciais foram carregadas antes de instanciar."""
        if not self.gateway_url:
            raise ValueError("SANKHYA_GATEWAY_URL ausente no .env")
        if not self.client_id or not self.client_secret or not self.token:
            raise ValueError("Credenciais do Sankhya incompletas no .env (ID, Secret ou Token)")

    def authenticate(self) -> bool:
        """
        Realiza a requisição POST para obter o token de acesso (Bearer JWT).
        Retorna True se o login for bem-sucedido, False caso contrário.
        """
        # Extrai o domínio base para chamar a rota /authenticate correta
        # Ex: de 'https://api.sankhya.com.br/gateway/v1' para 'https://api.sankhya.com.br'
        base_domain = self.gateway_url.split("/gateway")[0]
        auth_url = f"{base_domain}/authenticate"

        payload = {
            "grant_type": "client_credentials",
            "client_id": self.client_id,
            "client_secret": self.client_secret
        }
        
        headers = {
            "Content-Type": "application/x-www-form-urlencoded",
            "X-Token": self.token
        }

        try:
            response = requests.post(auth_url, data=payload, headers=headers)
            response.raise_for_status() # Lança exceção se o status não for 2xx
            
            # Salva o token temporário retornado pela API
            self.access_token = response.json().get("access_token")
            return True
            
        except requests.exceptions.RequestException as e:
            print(f"Erro na autenticação da API Sankhya: {e}")
            if hasattr(e, 'response') and e.response is not None:
                print(f"Detalhes do erro: {e.response.text}")
            return False

    def get_headers(self) -> Dict[str, str]:
        """
        Gera os cabeçalhos HTTP padrão necessários para consumo dos endpoints do Gateway.
        """
        headers = {
            "Content-Type": "application/json",
            "Accept": "application/json",
            "x-token": self.token
        }
        
        # Só injeta o Bearer se o authenticate() já tiver sido rodado com sucesso
        if self.access_token:
            headers["Authorization"] = f"Bearer {self.access_token}"
            
        return headers