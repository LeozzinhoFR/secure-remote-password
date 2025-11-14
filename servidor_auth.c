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
const int a_inv = 21; // O inverso modular de 5 (mod 26)
const int m = 26;

// Função de decifragem Afim (só para A-Z)
void affine_decrypt(char *msg) {
    int i = 0;
    while (msg[i] != '\0') {
        if (msg[i] >= 'A' && msg[i] <= 'Z') {
            // D(y) = a_inv * (y - 'A' - b) mod m
            int y = msg[i] - 'A';
            int p = (a_inv * (y - b + m)) % m; // +m para garantir que (y-b) seja positivo
            msg[i] = (char)(p + 'A');
        }
        i++;
    }
}

// Função para verificar usuário e senha no arquivo
int check_auth(const char *user, const char *pass) {
    FILE *fp;
    char line[256];
    char stored_user[100];
    char stored_pass[100];
    int authenticated = 0;

    fp = fopen("senhas.txt", "r");
    if (fp == NULL) {
        printf("[SERVIDOR] ERRO: Nao foi possivel abrir 'senhas.txt'\n");
        return 0;
    }

    while (fgets(line, sizeof(line), fp)) {
        line[strcspn(line, "\n")] = 0; // Remove newline

        // Tenta parsear a linha no formato "usuario:senha"
        char *token = strtok(line, ":");
        if (token != NULL) {
            strcpy(stored_user, token);
            token = strtok(NULL, ""); // Pega o resto da linha
            if (token != NULL) {
                strcpy(stored_pass, token);

                // Compara
                if (strcmp(user, stored_user) == 0 && strcmp(pass, stored_pass) == 0) {
                    authenticated = 1;
                    break;
                }
            }
        }
    }

    fclose(fp);
    return authenticated;
}


int main() {
    WSADATA wsaData;
    SOCKET socket_servidor, socket_cliente;
    struct sockaddr_in endereco_servidor, endereco_cliente;
    int tamanho_cliente;
    char buffer[TAM_BUFFER];
    int n_bytes;

    printf("[SERVIDOR] Inicializando Winsock...\n");
    if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0) {
        printf("Falha ao inicializar o Winsock. Erro: %d\n", WSAGetLastError());
        return 1;
    }

    socket_servidor = socket(AF_INET, SOCK_STREAM, 0);
    if (socket_servidor == INVALID_SOCKET) {
        printf("Erro ao criar o socket. Erro: %d\n", WSAGetLastError());
        WSACleanup();
        return 1;
    }

    memset(&endereco_servidor, 0, sizeof(endereco_servidor));
    endereco_servidor.sin_family = AF_INET;
    endereco_servidor.sin_addr.s_addr = INADDR_ANY;
    endereco_servidor.sin_port = htons(PORTA);

    if (bind(socket_servidor, (struct sockaddr *)&endereco_servidor, sizeof(endereco_servidor)) == SOCKET_ERROR) {
        printf("Erro ao fazer o bind. Erro: %d\n", WSAGetLastError());
        closesocket(socket_servidor);
        WSACleanup();
        return 1;
    }

    if (listen(socket_servidor, 5) == SOCKET_ERROR) {
        printf("Erro ao escutar. Erro: %d\n", WSAGetLastError());
        closesocket(socket_servidor);
        WSACleanup();
        return 1;
    }

    printf("[SERVIDOR] Aguardando conexoes na porta %d...\n", PORTA);

    tamanho_cliente = sizeof(endereco_cliente);
    socket_cliente = accept(socket_servidor, (struct sockaddr *)&endereco_cliente, &tamanho_cliente);
    if (socket_cliente == INVALID_SOCKET) {
        printf("Erro ao aceitar conexao. Erro: %d\n", WSAGetLastError());
        closesocket(socket_servidor);
        WSACleanup();
        return 1;
    }
    
    printf("[SERVIDOR] Conexao aceita.\n");
    closesocket(socket_servidor); // Fecha o de escuta, só aceita 1 cliente

    memset(buffer, 0, TAM_BUFFER);
    n_bytes = recv(socket_cliente, buffer, TAM_BUFFER - 1, 0);
    
    if (n_bytes <= 0) {
        printf("[SERVIDOR] Erro ao receber dados ou conexao fechada pelo cliente.\n");
    } else {
        printf("[SERVIDOR] Dados brutos recebidos: %s\n", buffer);

        // --- Lógica de Autenticação e Parse ---
        char *user = strtok(buffer, ":");
        char *pass = strtok(NULL, ":");
        char *msg_cifrada = strtok(NULL, "\0"); // Pega todo o resto

        if (user && pass && msg_cifrada) {
            printf("[SERVIDOR] Tentativa de login de: '%s'\n", user);

            if (check_auth(user, pass)) {
                printf("[SERVIDOR] AUTENTICADO!\n");
                printf("[SERVIDOR] Mensagem cifrada recebida: %s\n", msg_cifrada);
                
                affine_decrypt(msg_cifrada);
                
                printf("[SERVIDOR] Mensagem DECIFRADA: %s\n", msg_cifrada);
            } else {
                printf("[SERVIDOR] FALHA DE AUTENTICACAO para o usuario '%s'.\n", user);
            }
        } else {
            printf("[SERVIDOR] Formato de dados invalido recebido.\n");
        }
    }

    closesocket(socket_cliente);
    WSACleanup();
    printf("[SERVIDOR] Conexao fechada.\n");

    return 0;
}