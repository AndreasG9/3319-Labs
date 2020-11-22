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
#include "cryptopp820/base64.h"
#include "cryptopp820/files.h"

#define DEFAULT_PORT_NUM 8000 
#define BUFFER_LENGTH 512 

#define ID_CA "ID-CA"
#define ID_S "ID-Server"
#define LIFETIME_SESS 86400

long long int get_epoch_time_seconds(); 
std::string encrypt_rsa(CryptoPP::RSA::PublicKey key, std::string plain);
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


  // Read des_key 
  //std::string des_key_string;
  //std::cout << "des_key_string:" << des_key_string << std::cout; 


  //  ===================== GET PUBLIC KEY PK_CA  ===================================================
  // CryptoPP::RSA::PublicKey was encoded and stored in "public_key.txt"
  // Read, decode, and init CryptoPP::RSA::PublicKey to have CA's public key 

  CryptoPP::ByteQueue bytes;
  CryptoPP::FileSource file("public_key.txt", true, new CryptoPP::Base64Decoder);
  file.TransferTo(bytes);
  bytes.MessageEnd();

  CryptoPP::RSA::PublicKey PK_CA;
  PK_CA.Load(bytes);
  
  //  ===================== Network Setup (Winsock) to connect to CA first ===================================================

  WSADATA wsa_data;

  // Init Winsock 
  int retval = WSAStartup(MAKEWORD(2, 2), &wsa_data);
  if (retval != 0) {
    std::cout << "Error, WSAStartup failed" << std::endl;
    return 1;
  }

  // Prepare sockaddr_in structure
  struct sockaddr_in ca;

  ca.sin_family = AF_INET;
  ca.sin_addr.s_addr = inet_addr("127.0.0.1");
  ca.sin_port = htons(port_num); // default is 8000

  // Create Socket (server to connect) 
  SOCKET connected_socket;

  connected_socket = socket(AF_INET, SOCK_STREAM, 0);
  if (connected_socket == INVALID_SOCKET) {
    std::cout << "Error, socket creation failed" << std::endl;
    WSACleanup();
    return 1;
  }

  // --------------- Connect to CA -------------------
  retval = connect(connected_socket, (struct sockaddr*)&ca, sizeof(ca));
  if (retval == SOCKET_ERROR) {
    std::cout << "Error, failed to connect" << std::endl;
    closesocket(connected_socket);
    WSACleanup();
    return 1;
  }

  std::cout << "(S) Connected to (CA)" << std::endl << std::endl;

  char message_receive[BUFFER_LENGTH] = { 0 };
  int retval_send = 0, retval_receive = 0;

  std::string plaintext, ciphertext; 

  while (true) {

    //  ===================== STEP 1, Register w/ CA ===================================================
  
    // temp DES key (testing) CHANGE LATER
    std::string temp_des = "aBcjEFg4";

    plaintext.clear();
    plaintext += temp_des; 
    plaintext += ID_S;
    plaintext += std::to_string(get_epoch_time_seconds());

    // Encrypt using, CA's public key: PK_CA
    ciphertext = encrypt_rsa(PK_CA, plaintext);


    do {
      // Prompt server if ready to register with CA
      std::cout << "Register with CA (RSA_PK_CA[K_TMP1 || ID_S || TS_1])? hit any key to confirm ...\n";
    } while (std::cin.get() != '\n');


    // Send info to register with CA 
    retval_send = send(connected_socket, ciphertext.c_str(), ciphertext.size(), 0);
    if (retval_send == SOCKET_ERROR) {
      std::cout << "Error, failed to send" << std::endl;
      closesocket(connected_socket);
      WSACleanup();
      return 1;
    }

    std::cout << "\n(S) Waiting to receive a message from CA ... \n" << std::endl;



  }


  // close old socket

  // CONNECT to C (client.cpp)

  //shutdown(connected_socket2, SD_SEND);
  //closesocket(connected_socket2);
  //WSACleanup();
  std::cout << "(S) Server closed" << std::endl;


  return 0; 
}

long long int get_epoch_time_seconds() {
  // get time stamp (epoch equivalent) 

  long long int time = std::chrono::duration_cast<std::chrono::seconds>(std::chrono::system_clock::now().time_since_epoch()).count();

  return time;
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





