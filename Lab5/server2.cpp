/*
  Andreas Gagas
  3319 - Wireless Networks and Security
  Lab05 - Implementation and Application of Kerberos

  server2.cpp - V server
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


#define DEFAULT_PORT_NUM 8001 
#define BUFFER_LENGTH 512 

#define ID_C "CIS3319USERID"
#define ID_TGS "CIS3319TGSID"
#define ID_V "CIS3319SERVERID"
#define LIFETIME_2 60
#define LIFETIME_4 86400


std::string decrypt(std::string key_string, std::string ciphertext);
std::string encrypt(std::string key_string, std::string plaintext);
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

  // Get keys 
  std::string key_c_string, key_tgs_string, key_v_string;
  std::ifstream read_keys("keys.txt");

  if (read_keys.is_open()) {
    getline(read_keys, key_c_string);
    getline(read_keys, key_tgs_string);
    getline(read_keys, key_v_string);
  }

  read_keys.close();

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
  server.sin_port = htons(port_num);  // default is 8001

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
  int retval_send = 0, retval_receive = 0;

  std::string plaintext, ciphertext, msg, key_c_v, ticket_v;
  while (true) {

    std::cout << "\n(V) waiting to receive client info ... \n" << std::endl;

    // Receive TICKET_V || AUTH_C from C 
    while ((retval_receive = recv(client_socket, message_receive, BUFFER_LENGTH, 0)) > 0) {

      if (retval_receive > 0) {
        msg.clear();
        msg.append(message_receive, retval_receive);


        // split (tricky b/c of added padding) to get TICKET_V, and decrypt using key_v 
        int before_padding = 8 + strlen(ID_C) + AD_C.size() + strlen(ID_V) + 10 + std::to_string(LIFETIME_4).size(); 
        int r = before_padding % 8; 

        // the size of ticket_v will be 64-bytes before padding (but here we are not assuming that), padding will bring the ct to 72 bytes 
        // same for auth_c, it will be 36 bytes before and 40 after, but this is just for design purposes. 
        int after_padding; 
        if (r = 0) after_padding = before_padding + 8; 
        else after_padding = before_padding + (8 - before_padding % 8); // next multiple of 8

        ticket_v = msg.substr(0, after_padding);
        ticket_v = decrypt(key_v_string, ticket_v);
        //std::cout << "TICKET V: " << ticket_v << std::endl;

        // VALIDATE ticket time, valid if (current - TS_4) < LIFETIME_4 
        // split to get TS_4
        int start = 8 + strlen(ID_C) + AD_C.size() + strlen(ID_V);
        std::string TS_4 = ticket_v.substr(start, 10); // time string will be bytes 
        //std::cout << "TS_4: " << TS_4 << std::endl; 

        int current_t = get_epoch_time_seconds();
        int valid = current_t - std::stoi(TS_4);
        std::string validity = valid < LIFETIME_4 ? "true" : "false";

        // extract k_c_v to decrypt auth_c 
        key_c_v = ticket_v.substr(0, 8); // k_c_v generated as 8 byte key 

        // decrypt auth_c using key_c_v
        std::string auth_c = msg.substr(after_padding); 
        auth_c = decrypt(key_c_v, auth_c); 
        //std::cout << "AUTH_C: " << auth_c << std::endl; 

        // both decrypted, concat back together
        plaintext = ticket_v + auth_c; 

        // Print received msg (both ticket_v and auth_c decrypted) and validity
        std::cout << "\n***************************************************************" << std::endl;
        std::cout << "(V) received msg (both decrypted) is: " << plaintext << std::endl;  
        std::cout << "(V) split Ticket_v: " << ticket_v << std::endl;
        std::cout << "(V) split Auth_c: " << auth_c << std::endl;
        std::cout << "(V) valid message (current_t - TS_4 = " << valid << ") < " << LIFETIME_4 << ": " << validity << std::endl;
        std::cout << "*****************************************************************\n" << std::endl;
        break; // V turn to send msg 
      }

      // ========================= Step (6) ===========================
      // send E(K_C_V[TS_5 + 1]), service will be granted to C, we are done

      long long int TS_5 = get_epoch_time_seconds() + 1; 
      plaintext.clear();
      plaintext += std::to_string(TS_5);
      ciphertext = encrypt(key_c_v, plaintext);

      retval_send = send(client_socket, ciphertext.c_str(), ciphertext.size(), 0);
      if (retval_send == SOCKET_ERROR) {
        std::cout << "Error, failed to send" << std::endl;
        closesocket(client_socket);
        WSACleanup();
        return 1;
      }
      break; 
    }
    if (retval_receive < 0) break; 
  }


  // client disconnected, cleanup, quit server. 
  shutdown(client_socket, SD_SEND);
  closesocket(client_socket);
  WSACleanup();
  std::cout << "Server (V) closed" << std::endl;

  return 0; 
}

long long int get_epoch_time_seconds() {
  // get time stamp (epoch equivalent) 

  long long int time = std::chrono::duration_cast<std::chrono::seconds>(std::chrono::system_clock::now().time_since_epoch()).count();

  return time;
}

std::string encrypt(std::string key_string, std::string plaintext) {

  std::cout << plaintext.size() << std::endl;

  CryptoPP::SecByteBlock key((const unsigned char*)(key_string.data()), key_string.size());
  std::string ciphertext;

  try {
    CryptoPP::ECB_Mode< CryptoPP::DES >::Encryption encrypt;
    encrypt.SetKey(key, key.size());

    // Encrypt, add padding if needed 
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

  return ciphertext;
}

std::string decrypt(std::string key_string, std::string ciphertext) {

  CryptoPP::SecByteBlock key((const unsigned char*)(key_string.data()), key_string.size());
  std::string plaintext;

  try {

    CryptoPP::ECB_Mode< CryptoPP::DES >::Decryption decrypt;
    decrypt.SetKey(key, key.size());

    // Decrypt, remove padding if needed 
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


  return plaintext;
}

