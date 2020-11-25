/*
  Andreas Gagas
  3319 - Wireless Networks and Security
  Lab06 -Implement PKI-Based Authentication
  client.cpp - this is client
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
#define BUFFER_LENGTH 1024 

#define ID_CA "ID-CA"
#define ID_C "ID-Client"
#define ID_S "ID-Server"

long long int get_epoch_time_seconds();
std::string gen_tmp_key();
std::string encode_hex(std::string ct);

std::string encrypt_rsa(CryptoPP::RSA::PublicKey key, std::string plain);

std::string decrypt_des(std::string key_string, std::string ciphertext);


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

  //  ===================== Network Setup (Winsock) to connect to S ===================================================
  WSADATA wsa_data;

  // Init Winsock 
  int retval = WSAStartup(MAKEWORD(2, 2), &wsa_data);
  if (retval != 0) {
    std::cout << "Error, WSAStartup failed" << std::endl;
    return 1;
  }

  // Prepare sockaddr_in structure
  struct sockaddr_in server;

  server.sin_family = AF_INET;
  server.sin_addr.s_addr = inet_addr("127.0.0.1");
  server.sin_port = htons(port_num); // default is 8000

  // Create Socket (client to connect) 
  SOCKET connected_socket;

  connected_socket = socket(AF_INET, SOCK_STREAM, 0);
  if (connected_socket == INVALID_SOCKET) {
    std::cout << "Error, socket creation failed" << std::endl;
    WSACleanup();
    return 1;
  }

  // --------------- Connect to CA -------------------
  retval = connect(connected_socket, (struct sockaddr*)&server, sizeof(server));
  if (retval == SOCKET_ERROR) {
    std::cout << "Error, failed to connect" << std::endl;
    closesocket(connected_socket);
    WSACleanup();
    return 1;
  }

  std::cout << "(C) Connected to (S)" << std::endl << std::endl;

  char message_receive[BUFFER_LENGTH] = { 0 };
  int retval_send = 0, retval_receive = 0;

  std::string plaintext;

  while (true) {

    // ====================== STEP 3 ==========================
    plaintext = ID_S; 
    plaintext += std::to_string(get_epoch_time_seconds()); // TS_3


    // send ID_S || TS_3
    do {
      // Prompt user if ready to send msg to S
      std::cout << "Send msg to S (ID_S || TS_3)? hit any key to confirm ...\n";
    } while (std::cin.get() != '\n');

    // Send auth info to AS 
    retval_send = send(connected_socket, plaintext.c_str(), plaintext.size(), 0);
    if (retval_send == SOCKET_ERROR) {
      std::cout << "Error, failed to send" << std::endl;
      closesocket(connected_socket);
      WSACleanup();
      return 1;
    }



    // Print sent plaintext 
    std::cout << "\n***************************************************************" << std::endl;
    std::cout << "(C) sent plaintext is: " << plaintext << std::endl << std::endl;;
    std::cout << "****************************************************************\n" << std::endl;


    std::cout << "\n(C) Waiting to receive a message from S ... \n" << std::endl;

    // receive step 4 ... PK_S || CERT_S || TS_4
    while ((retval_receive = recv(connected_socket, message_receive, BUFFER_LENGTH, 0)) > 0) {
      if (retval_receive > 0) {
        // store received pt in c++ string 
        plaintext.clear();
        plaintext.append(message_receive, retval_receive);


        // Print received plaintext 
        std::cout << "\n***************************************************************" << std::endl;
        std::cout << "(C) received plaintext is: " << plaintext << std::endl << std::endl;;
        std::cout << "****************************************************************\n" << std::endl;

        break;
      }
    }


  }
  
  shutdown(connected_socket, SD_SEND);
  closesocket(connected_socket);
  WSACleanup();

  return 0; 
}

long long int get_epoch_time_seconds() {
  // get time stamp (epoch equivalent) 

  long long int time = std::chrono::duration_cast<std::chrono::seconds>(std::chrono::system_clock::now().time_since_epoch()).count();

  return time;
}

std::string gen_tmp_key() {
  // generate 8-byte string to be used as temp. des key 

  std::string chars = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";
  srand(time(0));
  std::string temp;

  for (int i = 0; i < 8; ++i) {
    temp += chars[rand() % chars.size()];
  }

  return temp;
}

std::string encode_hex(std::string ct) {

  std::string encoded;

  CryptoPP::StringSource(ct, true,
    new CryptoPP::HexEncoder(
      new CryptoPP::StringSink(encoded)
    )
  );

  return encoded;

}

std::string encrypt_rsa(CryptoPP::RSA::PublicKey key, std::string plain) {
  // RSA encryption (RSAES encryption scheme (OAEP using SHA-256). use CryptoPP filters to do so ...)

  CryptoPP::AutoSeededRandomPool rng;
  CryptoPP::RSAES_OAEP_SHA_Encryptor e(key);
  std::string cipher;

  CryptoPP::StringSource(plain, true,
    new CryptoPP::PK_EncryptorFilter(rng, e,
      new CryptoPP::StringSink(cipher)
    )
  );

  return cipher;
}

std::string decrypt_des(std::string key_string, std::string ciphertext) {

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