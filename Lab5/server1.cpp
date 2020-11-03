/*
  Andreas Gagas
  3319 - Wireless Networks and Security
  Lab05 - Implementation and Application of Kerberos

  server1.cpp - AS and TGS server
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




#define DEFAULT_PORT_NUM 8000 
#define BUFFER_LENGTH 512 

#define ID_V "CIS3319SERVERID"
#define ID_TGS "CIS3319TGSID"
#define ID_C "CIS3319USERID"
#define LIFETIME_2 60

long long int get_epoch_time_seconds(); 

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
  std::cout << "AD_C: " << AD_C << std::endl; 

  // Get keys 
  std::string key_c_string, key_tgs_string, key_v_string; 
  std::ifstream read_keys("keys.txt");

  if (read_keys.is_open()) {
    getline(read_keys, key_c_string);
    getline(read_keys, key_tgs_string);
    getline(read_keys, key_v_string);
  }

  read_keys.close();

  std::cout << key_c_string << "\n" << key_tgs_string << "\n" << key_v_string << std::endl; 

  // Init keys 
  CryptoPP::SecByteBlock key_c((const unsigned char*)(key_c_string.data()), key_c_string.size());
  CryptoPP::SecByteBlock key_tgs((const unsigned char*)(key_tgs_string.data()), key_tgs_string.size());
  CryptoPP::SecByteBlock key_v((const unsigned char*)(key_v_string.data()), key_v_string.size());

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

  char message_receive[BUFFER_LENGTH] = { 0 };
  int retval_send = 0, retval_recieve = 0;

  std::string encoded, plaintext, ciphertext, user; 

  // ----------- Main Loop ( Client(C) is connected to Server1(AS && TGS) ---------------------------------------------- 

  while (true) {
    // recieve and send data to client, until client disconnects

    ciphertext.clear();
    std::cout << "\n server1 AS waiting to receive client info ... \n" << std::endl;

    // client will send info to AS
    while ((retval_recieve = recv(client_socket, message_receive, BUFFER_LENGTH, 0)) > 0) {

      if (retval_recieve > 0) {
        user.clear();
        user.append(message_receive, retval_recieve);

        // AS side display (receive user info msg) 
        std::cout << "\n********************" << std::endl;
        std::cout << "(AS) received message is: " << user << std::endl;
        std::cout << "********************\n" << std::endl;

        // SPLIT Received msg to get ID_C, TS_1 (ID_TGS already defined) ?? or just use hard-coded values


        // Generate K_C_TGS (session key), size will be 64-bits TODO
        std::string key_c_tgs = "temp"; 


        // Ticket_TGS = E(K_TGS, [K_C_TGS || ID_C || AD_C || ID_TGS || TS_2 || LIFETIME_2) 
        std::string ticket_tgs; 
        std::string TS_2 = std::to_string(get_epoch_time_seconds()); 
        std::string ticket = key_c_tgs + ID_C + AD_C + ID_TGS + TS_2 + std::to_string(LIFETIME_2);

        std::cout << "ticket before ticket_tgs: " << ticket << std::endl; 

        // Encrypt ticket using DES with key_tgs to get ticket_tgs
        try {

          CryptoPP::ECB_Mode< CryptoPP::DES >::Encryption encrypt; // ECB
          encrypt.SetKey(key_tgs, key_tgs.size());

          // Encrpyt, add padding if needed 
          ticket_tgs.clear();
          CryptoPP::StringSource(ticket, true,
            new CryptoPP::StreamTransformationFilter(encrypt,
              new CryptoPP::StringSink(ticket_tgs)
            )
          );
        }
        catch (const CryptoPP::Exception& err) {
          std::cerr << "ERROR" << err.what() << std::endl;
          exit(1);
        }

        // msg concatenation 
        plaintext.clear();
        plaintext += key_c_tgs;
        plaintext += ID_TGS;
        plaintext += TS_2; 
        plaintext += std::to_string(LIFETIME_2); 
        plaintext += ticket_tgs; 

        // E(K_C, [K_C_TGS || ID_C ||AD_C || ID_TGS || TS_2 || Lifetime_2]) using DES with key K_C 
        try {

          CryptoPP::ECB_Mode< CryptoPP::DES >::Encryption encrypt; // ECB
          encrypt.SetKey(key_c, key_c.size());

          // Encrpyt, add padding if needed 
          ciphertext.clear();
          CryptoPP::StringSource(plaintext, true,
            new CryptoPP::StreamTransformationFilter(encrypt,
              new CryptoPP::StringSink(ciphertext)
            )
          );
        }
        catch (const CryptoPP::Exception& err) {
          std::cerr << "ERROR" << err.what() << std::endl;
          exit(1);
        }

        // SEND ENCRYPTED MSG (TICKET_TGS + other info) to client
        retval_send = send(client_socket, ciphertext.c_str(), ciphertext.size(), 0);
        if (retval_send == SOCKET_ERROR) {
          closesocket(client_socket);
          WSACleanup();
          return 1;
        }


        // TICKET-GRANTING SERVER (AS)




      }

      if (retval_recieve < 0) break;
    }

  }

	return 0;
}


long long int get_epoch_time_seconds() {
  // get time stamp (epoch equivalent) 

  long long int time = std::chrono::duration_cast<std::chrono::seconds>(std::chrono::system_clock::now().time_since_epoch()).count();

  return time;
}