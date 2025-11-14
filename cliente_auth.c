#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <winsock2.h>
#include <ws2tcpip.h>

#pragma comment(lib, "ws2_32.lib")

#define PORTA 8080
#define TAM_BUFFER 1024

// --- Criptografia Afim (Chaves) ---
const int a = 5;
const int b = 8;
const int m = 26;

// Função de cifragem Afim (só para A-Z)
void affine_encrypt(char *msg) {
    int i = 0;
    while (msg[i] != '\0') {
        if (msg[i] >= 'A' && msg[i] <= 'Z') {
            // E(x) = (a*x + b) mod m
            int x = msg[i] - 'A';
            int c = (a * x + b) % m;
            msg[i] = (char)(c + 'A');
        }
        i++;
    }
}

// Helper para remover o \n do fgets
void remove_newline(char *str) {
    str[strcspn(str, "\n")] = 0;
}

int main() {
    WSADATA wsaData;
    SOCKET socket_cliente;
    struct sockaddr_in endereco_servidor;
    char buffer[TAM_BUFFER];
    char usuario[100];
    char senha[100];
    char mensagem[TAM_BUFFER - 202]; // Deixa espaço para user e senha
    int n_bytes;

    printf("[CLIENTE] Inicializando Winsock...\n");
    if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0) {
        printf("Falha ao inicializar o Winsock. Erro: %d\n", WSAGetLastError());
        return 1;
    }

    socket_cliente = socket(AF_INET, SOCK_STREAM, 0);
    if (socket_cliente == INVALID_SOCKET) {
        printf("Erro ao criar o socket. Erro: %d\n", WSAGetLastError());
        WSACleanup();
        return 1;
    }

    memset(&endereco_servidor, 0, sizeof(endereco_servidor));
    endereco_servidor.sin_family = AF_INET;
    endereco_servidor.sin_port = htons(PORTA);
    endereco_servidor.sin_addr.s_addr = inet_addr("127.0.0.1");

    if (connect(socket_cliente, (struct sockaddr *)&endereco_servidor, sizeof(endereco_servidor)) == SOCKET_ERROR) {
        printf("Erro ao conectar ao servidor. Erro: %d\n", WSAGetLastError());
        closesocket(socket_cliente);
        WSACleanup();
        return 1;
    }
    printf("[CLIENTE] Conectado ao servidor na porta %d.\n", PORTA);

    // 1. Obter dados do usuário
    printf("Digite o usuario: ");
    fgets(usuario, 99, stdin);
    remove_newline(usuario);

    printf("Digite a senha: ");
    fgets(senha, 99, stdin);
    remove_newline(senha);

    printf("Digite a mensagem (APENAS MAIUSCULAS A-Z): ");
    fgets(mensagem, sizeof(mensagem) - 1, stdin);
    remove_newline(mensagem);

    // 2. Criptografar a MENSAGEM
    printf("[CLIENTE] Mensagem original: %s\n", mensagem);
    affine_encrypt(mensagem);
    printf("[CLIENTE] Mensagem CIFRADA: %s\n", mensagem);

    // 3. Formatar o buffer (usuario:senha:mensagem_cifrada)
    memset(buffer, 0, TAM_BUFFER);
    sprintf(buffer, "%s:%s:%s", usuario, senha, mensagem);

    // 4. Enviar (send) o buffer formatado
    n_bytes = send(socket_cliente, buffer, (int)strlen(buffer), 0);
    if (n_bytes == SOCKET_ERROR) {
        printf("Erro ao escrever no socket. Erro: %d\n", WSAGetLastError());
    } else {
        printf("[CLIENTE] Dados de autenticacao e mensagem enviados.\n");
    }

    // 5. Fechar o socket
    closesocket(socket_cliente);
    WSACleanup();
    printf("[CLIENTE] Conexao fechada.\n");

    return 0;
}