/*
  Andreas Gagas
  3319 - Wireless Networks and Security
  Lab06 -Implement PKI-Based Authentication
  ca.cpp - this is our toy certificate authority (CA)
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
#include "cryptopp820/base64.h"
#include "cryptopp820/files.h"

#define DEFAULT_PORT_NUM 8000 
#define BUFFER_LENGTH 512 

#define ID_CA "ID-CA"
#define ID_S "ID-Server"
#define LIFETIME_SESS 86400

long long int get_epoch_time_seconds();
std::string encrypt_rsa(CryptoPP::RSA::PublicKey key, CryptoPP::AutoSeededRandomPool rng, std::string plain);
std::string decrypt_rsa(CryptoPP::RSA::PrivateKey key, CryptoPP::AutoSeededRandomPool rng, std::string cipher);



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


  //  ===================== Generate RSA public/private keys and preshare PUBLIC key ===================================================
  CryptoPP::AutoSeededRandomPool rng;

  CryptoPP::InvertibleRSAFunction params; // params will include n,p,q,d,e 
  params.GenerateRandomWithKeySize(rng, 1024); // 1024 bits, could use a larger key size, but perfectably acceptable this demo

  CryptoPP::RSA::PrivateKey SK_CA(params); // private key 
  CryptoPP::RSA::PublicKey PK_CA(params); // public key

  // write public key PK_CA to a file, to "preshare"
  // use of CryptoPP to store CryptoPP::RSA::PublicKey in a file (instead of string with {n,e}). 

  CryptoPP::Base64Encoder public_key_sink(new CryptoPP::FileSink("public_key.txt"));
  PK_CA.DEREncode(public_key_sink);
  public_key_sink.MessageEnd();



 

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
  SOCKET ca_socket;

  ca_socket = socket(AF_INET, SOCK_STREAM, 0);
  if (ca_socket == INVALID_SOCKET) {
    std::cout << "Error, socket creation failed" << std::endl;
    WSACleanup();
    return 1;
  }

  // Bind (server socket address to socket desc.) 
  retval = bind(ca_socket, (struct sockaddr*)&server, sizeof(server));
  if (retval == SOCKET_ERROR) {
    std::cout << "Error, failed to bind" << std::endl;
    closesocket(ca_socket);
    WSACleanup();
    return 1;
  }

  // Listen
  retval = listen(ca_socket, SOMAXCONN);
  std::cout << std::endl << "Waiting for incoming connection from 127.0.0.1 on PORT: " << port_num << std::endl;
  if (retval == SOCKET_ERROR) {
    std::cout << "Error, failed to listen" << std::endl;
    closesocket(ca_socket);
    WSACleanup();
    return 1;
  }

  // Accept connection (we as CA, we accept connection from Application Server) 
  SOCKET server_socket;

  server_socket = accept(ca_socket, NULL, NULL);
  if (server_socket == INVALID_SOCKET) {
    std::cout << "Error, failed to accept connection" << std::endl;
    closesocket(ca_socket);
    WSACleanup();
    return 1;
  }

  std::cout << "(CA) Connected" << std::endl << std::endl;
  closesocket(ca_socket);

  char message_receive[BUFFER_LENGTH] = { 0 };
  int retval_send = 0, retval_receive = 0;

  std::string plaintext, ciphertext;





}

long long int get_epoch_time_seconds() {
  // get time stamp (epoch equivalent) 

  long long int time = std::chrono::duration_cast<std::chrono::seconds>(std::chrono::system_clock::now().time_since_epoch()).count();

  return time;
}

std::string encrypt_rsa(CryptoPP::RSA::PublicKey key, CryptoPP::AutoSeededRandomPool rng, std::string plain) {
  // RSA encryption (RSAES encryption scheme (OAEP using SHA-256). use CryptoPP filters to do so ...)

  std::string cipher;

  CryptoPP::RSAES_OAEP_SHA_Encryptor e(key);

  CryptoPP::StringSource(plain, true,
    new CryptoPP::PK_EncryptorFilter(rng, e,
      new CryptoPP::StringSink(cipher)
    )
  );

  return cipher;
}

std::string decrypt_rsa(CryptoPP::RSA::PrivateKey key, CryptoPP::AutoSeededRandomPool rng, std::string cipher) {
  // RSA decryption 

  std::string plain;

  CryptoPP::RSAES_OAEP_SHA_Decryptor d(key);

  CryptoPP::StringSource ss2(cipher, true,
    new CryptoPP::PK_DecryptorFilter(rng, d,
      new CryptoPP::StringSink(plain)
    )
  );

  return plain;
}

