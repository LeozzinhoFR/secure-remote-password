import hashlib
import secrets

# --- 1. Parâmetros Globais (Configuração do Grupo) ---
# Em produção, use os grupos RFC 5054 (ex: 2048 ou 4096 bits).
# Aqui uso valores pequenos apenas para demonstração visual.
N = '''00:c0:37:c3:75:88:b4:32:98:87:e6:1c:2d:a3:32:
       4b:1b:a4:b8:1a:63:f9:74:8f:ed:2d:8a:41:0c:2f:
       c2:1b:12:32:f0:d3:bf:a0:24:27:6c:fd:88:44:81:
       97:aa:e4:86:a6:3b:fc:a7:b8:bf:77:54:df:b3:27:
       c7:20:1f:6f:d1:7f:d7:fd:74:15:8b:d3:1c:e7:72:
       c9:f5:f8:ab:58:45:48:a9:9a:75:9b:5a:2c:05:32:
       16:2b:7b:62:18:e8:f1:42:bc:e2:c3:0d:77:84:68:
       9a:48:3e:09:5e:70:16:18:43:79:13:a8:c3:9c:3d:
       d0:d4:ca:3d:50:3b:66:25:ef:86:48:07:67:d1:93:
       bd:52:df:a6:18:c1:ed:06:36:47:58:76:c3:76:a5'''

# Convertendo o Hex para Inteiro
N_int = int("".join(N.split()).replace(":", ""), 16)
g = 2  # Gerador
k_hash = hashlib.sha256(f"{N_int}{g}".encode()).hexdigest()
k = int(k_hash, 16) # Multiplicador

def hash_sha256(*args):
    """Helper para criar hash de múltiplos argumentos."""
    concat = "".join(str(arg) for arg in args)
    return int(hashlib.sha256(concat.encode()).hexdigest(), 16)

# --- 2. Lado do Cliente (Registro) ---
class UserClient:
    def __init__(self, username, password):
        self.username = username
        self.password = password
        self.a = None # Segredo efêmero do cliente
        self.A = None # Valor público do cliente

    def register(self):
        """Gera o Salt e o Verificador para enviar ao servidor."""
        salt = secrets.token_hex(16)
        # x = H(salt | password)
        x = hash_sha256(salt, self.password)
        # v = g^x mod N
        v = pow(g, x, N_int)
        print(f"[Cliente] Gerando registro para '{self.username}'")
        return salt, v

    def start_login(self):
        """Passo 1: Gera 'a' e 'A'."""
        self.a = secrets.randbelow(N_int)
        self.A = pow(g, self.a, N_int)
        return self.username, self.A

    def finish_login(self, salt, B):
        """Passo 3: Calcula a chave de sessão."""
        # u = H(A | B)
        u = hash_sha256(self.A, B)
        
        if u == 0: raise Exception("Segurança comprometida (u=0)")

        # x = H(salt | password) Recalcula x
        x = hash_sha256(salt, self.password)

        # S_client = (B - k * g^x) ^ (a + u * x) mod N
        base = (B - (k * pow(g, x, N_int))) % N_int
        exponent = (self.a + (u * x))
        S = pow(base, exponent, N_int)
        
        K = hash_sha256(S) # Chave de sessão final
        return K

# --- 3. Lado do Servidor ---
class AuthServer:
    def __init__(self):
        self.db = {} # Simulação de banco de dados {user: (salt, v)}

    def save_user(self, username, salt, v):
        # Note que o servidor NÃO guarda a senha, só o verificador 'v'
        self.db[username] = {'salt': salt, 'v': v}
        print(f"[Servidor] Usuário '{username}' registrado. v={str(v)[:20]}...")

    def handle_login_step1(self, username, A):
        """Passo 2: Recebe A, gera 'b' e 'B'."""
        user_record = self.db.get(username)
        if not user_record:
            raise Exception("Usuário não encontrado")

        v = user_record['v']
        salt = user_record['salt']

        b = secrets.randbelow(N_int) # Segredo efêmero do servidor
        # B = k*v + g^b mod N
        B = (k * v + pow(g, b, N_int)) % N_int
        
        return salt, B, b # Retorna b apenas para uso interno no passo 2

    def handle_login_step2(self, username, A, B, b):
        """Passo 4: Calcula a chave de sessão do lado do servidor."""
        user_record = self.db.get(username)
        v = user_record['v']
        
        # u = H(A | B)
        u = hash_sha256(A, B)

        # S_server = (A * v^u)^b mod N
        base = (A * pow(v, u, N_int)) % N_int
        S = pow(base, b, N_int)
        
        K = hash_sha256(S)
        return K

# --- 4. Execução da Demonstração ---
if __name__ == "__main__":
    print("--- INÍCIO DO PROCESSO SRP ---")
    


    for i in range(2):
        print("\t|||||\n" * 4)
        print("Tentativa", i)
        # 1. Instanciar
        alice = UserClient("alice", "senha_super_secreta_123")
        server = AuthServer()
        print("-" * 20)


        # 2. Registro
        salt, v = alice.register()
        server.save_user("alice", salt, v)
        print("-" * 20)

        # 3. Login
        print("[Network] Alice inicia login...")
        user_name, A = alice.start_login()

        print("[Network] Servidor responde com desafio...")
        salt_resp, B, b_private = server.handle_login_step1(user_name, A)

        print("[Network] Ambos calculam a chave de sessão independentemente...")
        
        # Alice calcula sua chave
        try:
            client_key = alice.finish_login(salt_resp, B)
            print(f"[Alice]  Minha Chave Calculada: {str(client_key)[:20]}...")
        except Exception as e:
            print(f"Erro Alice: {e}")

        # Servidor calcula sua chave
        if i==0: 
            server_key = server.handle_login_step2(user_name, A, B, b_private)
            print(f"[Server] Minha Chave Calculada: {str(server_key)[:20]}...")
        else: #SUPOHAMOS QUE COLOQUE UMA SENHA ERRADA
            server_key = server.handle_login_step2(user_name, 65, B, b_private)
            print(f"[Server] Minha Chave Calculada: {str(server_key)[:20]}...")


        # 4. Verificação
        print("-" * 20)
        if client_key == server_key:
            print("SUCESSO! Autenticação segura realizada.")
            print("O servidor verificou a senha sem nunca recebê-la.")
            print("Ambos agora têm uma chave criptográfica compartilhada para a sessão.")
        else:
            print("FALHA! As chaves não conferem.")