/*
  Andreas Gagas
  3319 - Wireless Networks and Security
  Lab06 -Implement PKI-Based Authentication
  server.cpp - this is our application server
*/

#pragma comment(lib, "Ws2_32.lib")
#pragma comment(lib, "cryptlib.lib") 

#include <iostream>
#include <fstream>
#include <string>
#include <winsock2.h>
#include <ws2tcpip.h>
#include <chrono>
#include <cstdint>

#include "cryptopp820/cryptlib.h"
#include "cryptopp820/des.h"
#include "cryptopp820/osrng.h"
#include "cryptopp820/hex.h"
#include "cryptopp820/secblock.h"
#include "cryptopp820/modes.h"
#include "cryptopp820/rsa.h"

#define DEFAULT_PORT_NUM 8000 
#define BUFFER_LENGTH 512 

#define ID_CA "ID-CA"
#define ID_S "ID-Server"

long long int get_epoch_time_seconds(); 
std::string encrypt_rsa(CryptoPP::RSA::PublicKey key, std::string plain);
std::string decrypt_rsa(CryptoPP::RSA::PrivateKey key, std::string cipher);


int main(int argc, char** argv) {

  // Get port_num
  int port_num;

  if (argc == 1) port_num = DEFAULT_PORT_NUM;
  else port_num = atoi(argv[1]);

  if (argc > 2) {
    std::cout << "Too many args, include the port num or nothing";
    exit(1);
  }

  std::string AD_C = "127.0.01:" + std::to_string(port_num);

  // ====================== STEP 1 ("registers" with CA to get own public/private keys and cert) =======
  



  //  ===================== Network Setup (Winsock)  ===================================================

  // Init Winsock
  WSADATA wsa_data;

  int retval = WSAStartup(MAKEWORD(2, 2), &wsa_data);
  if (retval != 0) {
    std::cout << "Error, WSAStartup failed" << std::endl;
    return 1;
  }

  // Prepare sockaddr_in structure
  struct sockaddr_in server, client;

  server.sin_family = AF_INET;
  server.sin_addr.s_addr = INADDR_ANY; // default 127.0.0.1 
  server.sin_port = htons(port_num);  // default is 8000

  // Create Socket (server) 
  SOCKET server_socket;

  server_socket = socket(AF_INET, SOCK_STREAM, 0);
  if (server_socket == INVALID_SOCKET) {
    std::cout << "Error, socket creation failed" << std::endl;
    WSACleanup();
    return 1;
  }

  // Bind (server socket address to socket desc.) 
  retval = bind(server_socket, (struct sockaddr*)&server, sizeof(server));
  if (retval == SOCKET_ERROR) {
    std::cout << "Error, failed to bind" << std::endl;
    closesocket(server_socket);
    WSACleanup();
    return 1;
  }

  // Listen
  retval = listen(server_socket, SOMAXCONN);
  std::cout << std::endl << "Waiting for incoming connection from 127.0.0.1 on PORT: " << port_num << std::endl;
  if (retval == SOCKET_ERROR) {
    std::cout << "Error, failed to listen" << std::endl;
    closesocket(server_socket);
    WSACleanup();
    return 1;
  }

  // Accept connection (client) 
  SOCKET client_socket;

  client_socket = accept(server_socket, NULL, NULL);
  if (client_socket == INVALID_SOCKET) {
    std::cout << "Error, failed to accept connection" << std::endl;
    closesocket(server_socket);
    WSACleanup();
    return 1;
  }

  std::cout << "(S) Connected" << std::endl << std::endl;
  closesocket(server_socket);

  char message_receive[BUFFER_LENGTH] = { 0 };
  int retval_send = 0, retval_receive = 0;

  std::string plaintext, ciphertext; 








  return 0; 
}

long long int get_epoch_time_seconds() {
  // get time stamp (epoch equivalent) 

  long long int time = std::chrono::duration_cast<std::chrono::seconds>(std::chrono::system_clock::now().time_since_epoch()).count();

  return time;
}

std::string encrypt_rsa(CryptoPP::RSA::PublicKey key, std::string plain) {
  // RSA encryption (RSAES encryption scheme (OAEP using SHA-256). use CryptoPP filters to do so ...)




  return ""; 
}

std::string decrypt_rsa(CryptoPP::RSA::PrivateKey key, std::string cipher) {


  return "";
}