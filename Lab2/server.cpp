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

#include "cryptopp820/hmac.h"
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
  char message_receive[BUFFER_LENGTH] = { 0 };
  int retval_send = 0, retval_recieve = 0;
  std::string m1, m2, hmac_received, hmac_calculated, m1_concat_hmac, m2_concat_hmac, ciphertext;
  std::string encoded_mac_received, encoded_mac_calculated, encoded_ct;

  // Init keys 
  CryptoPP::SecByteBlock key_hmac((const unsigned char*)(key_hmac_string.data()), key_hmac_string.size());
  CryptoPP::SecByteBlock key_des((const unsigned char*)(key_des_string.data()), key_des_string.size());

  while (true) {
    // recieve and send data to client, until client disconnects

    std::cout << "\nWaiting to receive a message ... \n" << std::endl;

    // client will send an encrypted message/ chiphertext, store in c string, transfer data to c++ string  
    while ((retval_recieve = recv(client_socket, message_receive, BUFFER_LENGTH, 0)) > 0) {

      if (retval_recieve > 0) {
        // store received ciphertext in c++ string 
        ciphertext.clear();
        ciphertext.append(message_receive, retval_recieve);

        try {
          // Decrypt ciphertext using key_des, to get M1 || HMAC(K_HMAC, M1) 

          CryptoPP::ECB_Mode< CryptoPP::DES >::Decryption decrypt;
          decrypt.SetKey(key_des, key_des.size());

          // decrypt, remove padding if needed 
          m1_concat_hmac.clear();
          CryptoPP::StringSource (ciphertext, true,
            new CryptoPP::StreamTransformationFilter(decrypt,
              new CryptoPP::StringSink(m1_concat_hmac)
            )
          );
        }
        catch (const CryptoPP::Exception& err) {
          std::cerr << err.what() << std::endl;
          exit(1);
        }


        // SPLIT m1_concat_hmac to obtain M1 and HMAC(K_HMAC, M1) 
        hmac_received = m1_concat_hmac.substr((m1_concat_hmac.size() - 32), std::string::npos); // USED SHA-256, so the HMAC is the last 256 bits/ 32 bytes 

        // To verify, compute HMAC-SHA256(KEY_HMAC, M1) and compare hash 
        m1 = m1_concat_hmac.substr(0, m1_concat_hmac.size() - 32);

        try {
          // Generate a new HMAC-SHA256(K_HMAC, M1), store in hash_calculated 
          hmac_calculated.clear(); 
          CryptoPP::HMAC< CryptoPP::SHA256 > hmac(key_hmac, key_hmac.size());

          CryptoPP::StringSource (m1, true,
            new CryptoPP::HashFilter(hmac,
              new CryptoPP::StringSink(hmac_calculated)
            )
          );
        }

        catch (const CryptoPP::Exception& e) {
          std::cout << "ERROR" << std::endl;
        }
        

        // Display received ct as readable hex (for print statements)  
        encoded_ct.clear();
        CryptoPP::StringSource(ciphertext, true,
          new CryptoPP::HexEncoder(
            new CryptoPP::StringSink(encoded_ct)
          )
        );

        // Display received hash as readable hex 
        encoded_mac_received.clear();
        CryptoPP::StringSource(hmac_received, true,
          new CryptoPP::HexEncoder(
            new CryptoPP::StringSink(encoded_mac_received)
          )
        );

        // Display calculated hash as readable hex 
        encoded_mac_calculated.clear();
        CryptoPP::StringSource(hmac_calculated, true,
          new CryptoPP::HexEncoder(
            new CryptoPP::StringSink(encoded_mac_calculated)
          )
        );


        // Server side display (recieved data)
        std::cout << "\n\nSERVER SIDE" << std::endl;
        std::cout << "********************" << std::endl;
        std::cout << "received ciphertext is: " << encoded_ct << std::endl;
        std::cout << "received plaintext  is: " << m1 << std::endl;
        std::cout << "received hmac is  : " << encoded_mac_received << std::endl;
        std::cout << "calculated hmac is: " << encoded_mac_calculated << std::endl;

        if(hmac_received == hmac_calculated) std::cout << "HMAC Verified" << std::endl;
        else std::cout << "HMAC NOT Verified" << std::endl;

        std::cout << "********************\n" << std::endl;



        
        // Server's turn to send a message 
        m2.clear(); 
        std::cout << "Type message: ";
        std::getline(std::cin, m2);


        try {
          // HMAC-SHA256(K_HMAC, M2)
          hmac_calculated.clear(); 
          CryptoPP::HMAC< CryptoPP::SHA256 > hmac(key_hmac, key_hmac.size());

          CryptoPP::StringSource(m2, true,
            new CryptoPP::HashFilter(hmac,
              new CryptoPP::StringSink(hmac_calculated)
            )
          );
        }
        catch (const CryptoPP::Exception& err) {
          std::cerr << err.what() << std::endl;
          exit(1);
        }

        // Concatenate plaintext + HMAC, which is: M2 || HMAC(K_HMAC, M2) 
        m2_concat_hmac = m2 + hmac_calculated;

        try {
          // DES(K_DES, M2 || HMAC(K_HMAC, M2))  
          CryptoPP::ECB_Mode< CryptoPP::DES >::Encryption encrypt; // ECB mode       
          encrypt.SetKey(key_des, key_des.size());

          // Encrpyt, add padding if needed 
          ciphertext.clear();
          CryptoPP::StringSource(m2_concat_hmac, true,
            new CryptoPP::StreamTransformationFilter(encrypt,
              new CryptoPP::StringSink(ciphertext)
            )
          );
        }
        catch (const CryptoPP::Exception& err) {
          // encryption error 
          std::cerr << "ERROR" << err.what() << std::endl;
          exit(1);
        }

        // send ciphertext to client/C (as c string) 
        retval_send = send(client_socket, ciphertext.c_str(), ciphertext.size(), 0);
        if (retval_send == SOCKET_ERROR) {
          std::cout << "Error, failed to send" << std::endl;
          closesocket(client_socket);
          WSACleanup();
          return 1;
        }

        // Convert hmac to readable hex 
        encoded_mac_calculated.clear();
        CryptoPP::StringSource(hmac_calculated, true,
          new CryptoPP::HexEncoder(
            new CryptoPP::StringSink(encoded_mac_calculated)
          )
        );

        // Convert ciphertext to readable hex 
        encoded_ct.clear();
        CryptoPP::StringSource(ciphertext, true,
          new CryptoPP::HexEncoder(
            new CryptoPP::StringSink(encoded_ct)
          )
        );


        // Server side display (send data)
        std::cout << "\n\nSERVER SIDE" << std::endl;
        std::cout << "********************" << std::endl;
        std::cout << "Shared HMAC key is: " << key_hmac_string << std::endl;
        std::cout << "Shared DES key is : " << key_des_string << std::endl;
        std::cout << "plain message is : " << m2 << std::endl;
        std::cout << "server side HMAC is: " << encoded_mac_calculated << std::endl;
        std::cout << "sent ciphertext is: " << encoded_ct << std::endl;
        std::cout << "********************\n" << std::endl;


        std::cout << "\nWaiting to receive a message ... \n" << std::endl;
      }
    }
    if (retval_recieve < 0) break; // client disconnected or recv error, break out of main loop 
  }

  return 0; 
}