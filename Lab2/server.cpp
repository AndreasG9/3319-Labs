/*
  Andreas Gagas
  3319 - Wireless Networks and Security
  Lab02 - Implementation and Application of HMAC ( using SHA-256 )

  server.cpp
  // PS C:\Dev CS\Wireless Networks and Security\Lab2
*/

#pragma comment(lib, "Ws2_32.lib")
#pragma comment(lib, "cryptlib.lib") 

#include <iostream>
#include <fstream>
#include <string>
#include <winsock2.h>
#include <ws2tcpip.h>

#include "cryptopp820/cryptlib.h"
#include "cryptopp820/osrng.h"
#include "cryptopp820/hex.h"
#include "cryptopp820/secblock.h"
#include "cryptopp820/modes.h"

#include "cryptopp820/des.h"
#include "cryptopp820/sha.h"


#define DEFAULT_PORT_NUM 8000 
#define BUFFER_LENGTH 512 

int main(int argc, char** argv) {

  // Get Port # 
  int port_num;

  if (argc == 1) port_num = DEFAULT_PORT_NUM;
  else port_num = atoi(argv[1]);

  if (argc > 2) {
    std::cout << "Too many args, include the port num or nothing";
    exit(1);
  }

  // Get keys
  std::string key_hmac_string, key_des_string; 
  std::ifstream read_keys("key_hmac.txt");

  if (read_keys.is_open()) {
    // get key hmac (64 bytes)
    while(getline(read_keys, key_hmac_string)) {}
    read_keys.close(); 
  }

  read_keys.open("key_des.txt", std::ifstream::in);

  if (read_keys.is_open()) {
    // get key des (8 bytes) 
    while (getline(read_keys, key_des_string)) {}
    read_keys.close();
  }

  // ----------- Network Setup (Winsock) ----------------------------------------------

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

  std::cout << "Connected" << std::endl << std::endl;
  closesocket(server_socket);


  // ----------- Main Loop ( Client is connected ) ---------------------------------------------- 
  std::string encoded, plaintext, ciphertext;
  char message_receive[BUFFER_LENGTH] = { 0 };
  int retval_send = 0, retval_recieve = 0;

  CryptoPP::SHA256 hash;
  CryptoPP::SecByteBlock key_des((const unsigned char*)(key_des_string.data()), key_des_string.size()); // init key_des 


  while (true) {
    // recieve and send data to client, until client disconnects


    std::cout << "\nWaiting to receive a message ... \n" << std::endl;

    // client will send an encrypted message/ chiphertext, store in c string, transfer data to c++ string  
    while ((retval_recieve = recv(client_socket, message_receive, BUFFER_LENGTH, 0)) > 0) {


      if (retval_recieve > 0) {
        // second while loop to ensure we get ALL the sent bytes
        ciphertext.clear();
        ciphertext.append(message_receive, retval_recieve);

        // Hash w/ use of crypto++ filters 


      }
    }



  return 0; 
}