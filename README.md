# SRP (Secure Remote Password) Protocol - Python Proof of Concept

Este repositório contém uma implementação de demonstração do protocolo **SRP (Secure Remote Password)**, especificamente a variante SRP-6a. O objetivo é ilustrar como funciona uma autenticação de **Prova de Conhecimento Zero (Zero-Knowledge Proof)**, onde o servidor valida a senha do usuário sem nunca recebê-la, nem mesmo criptografada.

## 🧠 O Que é o SRP?

O SRP é um protocolo de "Troca de Chaves Autenticada por Senha" (PAKE). Ele resolve três problemas críticos de segurança:

1.  **Zero-Knowledge:** O servidor nunca vê a senha em texto claro.
2.  **Segurança do Banco de Dados:** O servidor armazena apenas um "Verificador" matemático. Se o banco vazar, o atacante não consegue obter as senhas facilmente (ao contrário de hashes simples).
3.  **Perfect Forward Secrecy:** Mesmo que a senha seja descoberta no futuro, sessões passadas não podem ser descriptografadas.

## 🚀 Como Executar

### Pré-requisitos
* Python 3.6+
* Nenhuma biblioteca externa é necessária (usa apenas `hashlib` e `secrets` da biblioteca padrão).

### Execução
1. Clone o repositório:
   ```bash
   git clone https://github.com/LeozzinhoFR/secure-remote-password
   cd srp-demo-python
``

2.  Execute o script:
   ```bash
   python srp_demo.py
```

## 📂 Estrutura do Código

O código é dividido em duas classes principais que simulam a interação Cliente-Servidor:

### 1\. `UserClient` (O Cliente/Usuário)

Simula o navegador ou app do usuário.

  * **Responsabilidade:** Guardar a senha em memória apenas durante o processo e realizar os cálculos matemáticos do lado do cliente.
  * **Método `register()`:** Gera um *Salt* aleatório e o *Verificador* ($v$) para enviar ao servidor.
  * **Método `finish_login()`:** Usa os dados públicos do servidor ($B$) e seus próprios dados secretos para derivar a Chave de Sessão ($K$).

### 2\. `AuthServer` (O Servidor)

Simula o backend de autenticação.

  * **Responsabilidade:** Armazenar o registro (Salt e Verificador) e emitir desafios. **O servidor não armazena a senha.**
  * **Método `handle_login_step1()`:** Recebe a intenção de login e retorna o desafio criptográfico ($B$).
  * **Método `handle_login_step2()`:** Verifica se a chave gerada pelo cliente bate com a chave calculada pelo servidor.

## 📝 Fluxo do Protocolo (Teoria vs Código)

O protocolo segue uma "dança" matemática baseada em aritmética modular. Veja como o código implementa as fórmulas do SRP-6a:

| Etapa | Ação | Fórmula Matemática (Simplificada) | No Código Python |
| :--- | :--- | :--- | :--- |
| **Registro** | Cliente gera Verificador | $x = H(s, p)$ <br> $v = g^x \pmod N$ | `client.register()` |
| **Login 1** | Cliente envia valor público $A$ | $a = random()$ <br> $A = g^a \pmod N$ | `client.start_login()` |
| **Login 2** | Servidor envia valor público $B$ | $b = random()$ <br> $B = kv + g^b \pmod N$ | `server.handle_login_step1()` |
| **Cálculo** | Ambos calculam a chave $S$ | $S_{cli} = (B - k g^x)^{a + ux}$ <br> $S_{srv} = (Av^u)^b$ | `finish_login()` & `handle_login_step2()` |

> **Nota:** Se a senha estiver correta, $S_{cli}$ e $S_{srv}$ serão idênticos, gerando a mesma chave de sessão $K$.

## ⚠️ Aviso de Segurança

Este código é uma **Prova de Conceito (PoC)** para fins educacionais.

  * **NÃO USE EM PRODUÇÃO:** Esta implementação não protege contra *timing attacks* (ataques de canal lateral) e usa parâmetros de grupo simplificados para demonstração.
  * Para produção, utilize bibliotecas validadas como `pysrp` ou `cryptography`.

## 👤 Autor

Desenvolvido por **Leonardo Felipe Roncolato** como parte de estudos em Segurança da Informação para Sistemas Distribuídos no curso de Ciência da Computação da PUC-GO.
