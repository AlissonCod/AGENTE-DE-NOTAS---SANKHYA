import threading
import tkinter as tk
import customtkinter as ctk
from typing import Any, Dict

# Importa as funções do seu script original
# (Ajuste o nome 'seu_script_original' para o nome real do seu arquivo .py)
from main import autenticar_sankhya, limpar_chave_nfe, processar_nfe

# Configuração global de aparência do CustomTkinter
ctk.set_appearance_mode("System")  # "System", "Dark" ou "Light"
ctk.set_default_color_theme("blue")  # "blue", "green" ou "dark-blue"


class AppAgenteFiscal(ctk.CTk):

    def __init__(self):
        super().__init__()

        # Configurações da Janela
        self.title("Sankhya AI - Conferência Fiscal TOP 1724")
        self.geometry("650x550")
        self.resizable(False, False)

        # Inicializa o cliente Sankhya (None até autenticar)
        self.client = None

        # ---------------------------------------------------------
        # COMPONENTES DA INTERFACE
        # ---------------------------------------------------------
        # Título principal
        self.titulo = ctk.CTkLabel(
            self,
            text="Conferência Fiscal de NF-e",
            font=ctk.CTkFont(size=22, weight="bold"),
        )
        self.titulo.pack(pady=(20, 5))

        self.subtitulo = ctk.CTkLabel(
            self,
            text="Validação automatizada de ICMS para a TOP 1724",
            font=ctk.CTkFont(size=13),
            text_color="gray",
        )
        self.subtitulo.pack(pady=(0, 20))

        # Input da Chave de Acesso
        self.lbl_chave = ctk.CTkLabel(
            self, text="Chave de Acesso da NF-e (44 dígitos):", anchor="w"
        )
        self.lbl_chave.pack(padx=40, fill="x")

        self.txt_chave = ctk.CTkEntry(
            self,
            placeholder_text="Cole os 44 números da chave aqui...",
            height=35,
        )
        self.txt_chave.pack(padx=40, pady=(5, 15), fill="x")

        # Botão de Ação
        self.btn_processar = ctk.CTkButton(
            self,
            text="Verificar Nota no Sankhya",
            height=40,
            font=ctk.CTkFont(weight="bold"),
            command=self.iniciar_processamento,
        )
        self.btn_processar.pack(padx=40, pady=10, fill="x")

        # Card de Status / Resultado
        self.card_status = ctk.CTkFrame(self, height=60, fg_color="transparent")
        self.card_status.pack(padx=40, pady=15, fill="x")

        self.lbl_status_resultado = ctk.CTkLabel(
            self,
            text="Aguardando inserção de chave...",
            font=ctk.CTkFont(size=14, weight="bold"),
            text_color="gray",
        )
        self.lbl_status_resultado.pack(pady=5)

        # Caixa de Texto para Logs / Detalhes do JSON
        self.lbl_detalhes = ctk.CTkLabel(
            self, text="Detalhes do Processamento:", anchor="w"
        )
        self.lbl_detalhes.pack(padx=40, fill="x")

        self.txt_logs = ctk.CTkTextbox(self, height=180, font=("Consolas", 12))
        self.txt_logs.pack(padx=40, pady=(5, 20), fill="both", expand=True)

        # Conectar ao inicializar (em uma thread separada para não travar a abertura do app)
        threading.Thread(target=self.conectar_sankhya_background, daemon=True).start()

    def conectar_sankhya_background(self):
        """Autentica na API do Sankhya sem congelar a interface."""
        self.atualizar_status("Autenticando na API Sankhya...", "gray")
        cliente = autenticar_sankhya()
        if cliente:
            self.client = cliente
            self.atualizar_status("Pronto para consulta", "teal")
        else:
            self.atualizar_status(
                "Erro Crítico: Falha na autenticação Sankhya", "red"
            )
            self.btn_processar.configure(state="disabled")

    def iniciar_processamento(self):
        """Dispara o processamento da nota em uma Thread dedicada."""
        chave = self.txt_chave.get().strip()

        if not chave:
            self.atualizar_status("Por favor, informe uma chave!", "orange")
            return

        # Desabilita o botão para evitar múltiplos cliques
        self.btn_processar.configure(state="disabled", text="Processando...")
        self.txt_logs.delete("1.0", tk.END)

        # Executa em Background para a interface continuar respondendo (ficar fluida)
        thread = threading.Thread(
            target=self.rodar_motor_fiscal, args=(chave,), daemon=True
        )
        thread.start()

    def rodar_motor_fiscal(self, chave_bruta: str):
        """Executa a lógica de limpeza e busca das regras fiscais."""
        try:
            chave_limpa = limpar_chave_nfe(chave_bruta)

            if not self.client:
                self.atualizar_ui_fim(
                    "Erro: Cliente Sankhya não autenticado.", "red", {}
                )
                return

            # Executa a sua função original!
            resultado = processar_nfe(self.client, chave_limpa)
            status = resultado.get("status", "DESCONHECIDO")
            mensagem = resultado.get("mensagem", "")

            # Define a cor do card baseado no status do seu motor
            cores = {
                "APROVADO": "#2ecc71",  # Verde moderno
                "REVISAO_MANUAL": "#f39c12",  # Laranja
                "FORA_DO_ESCOPO": "#34495e",  # Cinza escuro
                "DIVERGENTE": "#e74c3c",  # Vermelho
                "ERRO_TECNICO": "#c0392b",
            }
            cor_final = cores.get(status, "gray")

            texto_resultado = f"STATUS: {status}\n{mensagem}"
            self.atualizar_ui_fim(texto_resultado, cor_final, resultado)

        except ValueError as ve:
            self.atualizar_ui_fim(f"Erro de Validação:\n{ve}", "orange", {})
        except Exception as e:
            self.atualizar_ui_fim(f"Erro Inesperado:\n{e}", "red", {})

    def atualizar_status(self, texto: str, cor: str):
        """Muda o texto de status de forma segura entre as threads."""
        self.lbl_status_resultado.configure(text=texto, text_color=cor)

    def atualizar_ui_fim(self, texto_status: str, cor: str, dados_json: dict):
        """Devolve o controle para a Main Thread atualizar os componentes visuais."""
        self.lbl_status_resultado.configure(text=texto_status, text_color=cor)

        # Formata o JSON retornado para exibir na caixa de texto
        import json

        json_formatado = json.dumps(dados_json, indent=4, ensure_ascii=False)
        self.txt_logs.insert("1.0", json_formatado)

        # Reativa o botão
        self.btn_processar.configure(state="normal", text="Verificar Nota no Sankhya")


if __name__ == "__main__":
    app = AppAgenteFiscal()
    app.mainloop()