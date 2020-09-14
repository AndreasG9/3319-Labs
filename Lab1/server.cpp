/*
  Andreas Gagas
  3319 - Wireless Networks and Security 
  Lab01 - Implementation and Application of DES 

  server.cpp
  // PS C:\Dev CS\Wireless Networks and Security\Lab1
*/

#pragma comment(lib, "Ws2_32.lib")
#pragma comment(lib, "cryptlib.lib") 

#include <iostream>
#include <fstream>
#include <string>
#include <winsock2.h>
#include <ws2tcpip.h>

#include "cryptopp820/cryptlib.h"
#include "cryptopp820/des.h"
#include "cryptopp820/osrng.h"
#include "cryptopp820/hex.h"
#include "cryptopp820/secblock.h"
#include "cryptopp820/modes.h" // ECB 
#include "cryptopp820/files.h"
#include <vector>


#define DEFAULT_PORT_NUM 8000 
#define BUFFER_LENGTH 512 


int main(int argc, char **argv) {

  // ----------- PORT # -------------------------------------------------------------
  int port_num; 

  if (argc == 1) port_num = DEFAULT_PORT_NUM;
  else port_num = atoi(argv[1]); 

  if (argc > 2) {
    std::cout << "Too many args, include the port num or nothing";
    exit(1); 
  }


  // ----------- GET KEY, INIT -------------------------------------------------------------
  std::string key_string;
  std::ifstream read_key("key.txt");

  if (read_key.is_open()) {
    // store in c++ string 
    while (getline(read_key, key_string)) {}
    read_key.close();
  }
  
  // Init key for use with crypto++ 
  CryptoPP::SecByteBlock key((const unsigned char*)(key_string.data()), key_string.size());




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

  // ----------- Main Loop (Client is connected) ---------------------------------------------- 
  char message_send[BUFFER_LENGTH] = { 0 }, message_receive[BUFFER_LENGTH] = { 0 };
  int retval_send = 0, retval_recieve = 0;

  std::string encoded, plaintext, ciphertext;

  while (true) {
    // recieve and send data to client, until client disconnects

    ciphertext.clear();
    std::cout << "\nWaiting to receive a message ... \n" << std::endl;

    // client will send an encrypted message/ chiphertext, store in c string, transfer data to c++ string  
    while ((retval_recieve = recv(client_socket, message_receive, BUFFER_LENGTH, 0)) > 0) {


      if (retval_recieve > 0) {
        // second while loop to ensure we get ALL the sent bytes
        ciphertext.clear();
        ciphertext.append(message_receive, retval_recieve);


        try {
          // DECRYPT MESSAGE w/ crypto++ lib DES 

          CryptoPP::ECB_Mode< CryptoPP::DES >::Decryption decrypt; // ECB, no init vector needed 
          decrypt.SetKey(key, key.size());

          // Decrypt, remove padding if needed 
          plaintext.clear();
          CryptoPP::StringSource s(ciphertext, true,
            new CryptoPP::StreamTransformationFilter(decrypt,
              new CryptoPP::StringSink(plaintext)
            )
          );
        }

        catch (const CryptoPP::Exception& err) {
          std::cerr << "ERROR probably exceeded the buffer length\n" << err.what() << std::endl;
          exit(1);
        }

        // Display ciphertext as HEX
        encoded.clear();
        CryptoPP::StringSource(ciphertext, true,
          new CryptoPP::HexEncoder(
            new CryptoPP::StringSink(encoded)
          )
        );


        // Server side display (receive data) 
        std::cout << "\n********************\n" << std::endl;
        std::cout << "received ciphertext(hex) is: " << encoded << std::endl;
        std::cout << "received plaintext is: " << plaintext << std::endl;
        std::cout << "********************\n" << std::endl;

        


        // Server's turn to send a message 
        std::cout << "Type message: ";
        std::getline(std::cin, plaintext);

        try {

          CryptoPP::ECB_Mode< CryptoPP::DES >::Encryption encrypt; // ECB, no init vector needed 
          encrypt.SetKey(key, key.size());

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


        // send ciphertext to client/C. 
        retval_send = send(client_socket, ciphertext.c_str(), ciphertext.size(), 0);
        if (retval_send == SOCKET_ERROR) {
          closesocket(client_socket);
          WSACleanup();
          return 1;
        }

        // Display as HEX
        encoded.clear();
        CryptoPP::StringSource(ciphertext, true,
          new CryptoPP::HexEncoder(
            new CryptoPP::StringSink(encoded)
          )
        );


        // Server side display (sent data)
        std::cout << "\n\nHi, this is server." << std::endl;
        std::cout << "********************" << std::endl;
        std::cout << "key is: " << key_string << std::endl;
        std::cout << "sent plaintext is: " << plaintext << std::endl;
        std::cout << "sent ciphertext(hex) is: " << encoded << std::endl;
        std::cout << "********************\n" << std::endl;

        std::cout << "\nWaiting to receive a message ... \n" << std::endl;
      }
    }

    if (retval_recieve < 0) break; // client disconnected or recv error, break out of main loop 
  }



  // client disconnected, cleanup, quit server. 
  shutdown(client_socket, SD_SEND);
  closesocket(client_socket);
  WSACleanup();
  std::cout << "Server closed" << std::endl;

  return 0;
}