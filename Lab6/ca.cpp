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
std::string decrypt_rsa(CryptoPP::RSA::PrivateKey key, std::string cipher);
std::string sign_rsa(CryptoPP::RSA::PrivateKey SK_CA, std::string message);

std::string encrypt_des(std::string key_string, std::string plaintext);



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

  //  ===================== Generate CA pair of RSA public/private keys and preshare PUBLIC key ===================================================
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

  std::cout << "(CA) Connected to (S)" << std::endl << std::endl;
  closesocket(ca_socket);

  char message_receive[BUFFER_LENGTH] = { 0 };
  int retval_send = 0, retval_receive = 0;

  std::string plaintext, ciphertext;

  while (true) {
    
    std::cout << "\n (CA) Waiting to receive a message ... \n" << std::endl;

    // server will send RSA_PK_CA[K_tmp1 || ID_S || TS_1] 
    while ((retval_receive = recv(server_socket, message_receive, BUFFER_LENGTH, 0)) > 0) {

      if (retval_receive > 0) {
        ciphertext.clear();
        ciphertext.append(message_receive, retval_receive);

        // Decrypt using private key SK_CA to get K_TMP1 || ID_S || TS_1
        plaintext = decrypt_rsa(SK_CA, ciphertext);

        // Print out ciphertext and temp des key
        std::cout << "\n***************************************************************" << std::endl;
        std::cout << "(CA) received ciphertext: " << ciphertext << std::endl;
        std::cout << "(CA) received K_TMP1 " << plaintext.substr(0, 8) << std::endl;
        std::cout << "***************************************************************\n" << std::endl;

        //  ===================== STEP 2 ===================================================

        // Extract DES_K_TMP1 from plaintext 
        std::string k_tmp1 = plaintext.substr(0, 8); // been using 8-byte keys

        // Generate new public/private key pair for S (params defined above, key-size 1024) 
        CryptoPP::RSA::PrivateKey SK_S(params); // private key 
        CryptoPP::RSA::PublicKey PK_S(params); // public key

        // CONVERT RSA::PublicKey, RSA::PrivateKey to C++ STRINGS!
        std::string encoded_PK_S, encoded_SK_S;

        CryptoPP::StringSink sink(encoded_PK_S);
        PK_S.DEREncode(sink);

        CryptoPP::StringSink sink2(encoded_SK_S);
        SK_S.DEREncode(sink2);

        // Build Cert_S = Sign_SK_CA [ID_S || IC_CA || PK_S]
        std::string sign_sk_ca = ID_S;
        sign_sk_ca += ID_CA;
        sign_sk_ca += encoded_PK_S;

        // Sign 
        sign_sk_ca = sign_rsa(SK_CA, sign_sk_ca); 

        // Build PK_S || SK_S || CERT_S || ID_S || TS_2
        plaintext.clear();
        plaintext += encoded_PK_S;
        plaintext += encoded_SK_S;
        plaintext += sign_sk_ca;
        plaintext += ID_S;
        plaintext += std::to_string(get_epoch_time_seconds()); 

        // Encrypt using DES_K_TMP1
        ciphertext = encrypt_des(k_tmp1, plaintext);

        // SEND encrypted msg (new key pair, cert_s, etc...) to client
        retval_send = send(ca_socket, ciphertext.c_str(), ciphertext.size(), 0);
        if (retval_send == SOCKET_ERROR) {
          std::cout << "Error, failed to send" << std::endl;
          closesocket(ca_socket);
          WSACleanup();
          return 1;
        }

        break; // CA work is complete (server.cpp will disconnect ...)
      }
    }

    if (retval_receive <= 0) break; // server disconnected (likely connected to C, as work with CA done))
  }


  // cleanup
  shutdown(server_socket, SD_SEND);
  closesocket(server_socket);
  WSACleanup();
  std::cout << "CA closed" << std::endl;

  return 0; 
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

std::string decrypt_rsa(CryptoPP::RSA::PrivateKey key, std::string cipher) {
  // RSA decryption 

  CryptoPP::AutoSeededRandomPool rng;
  CryptoPP::RSAES_OAEP_SHA_Decryptor d(key);
  std::string plain;

  CryptoPP::StringSource ss2(cipher, true,
    new CryptoPP::PK_DecryptorFilter(rng, d,
      new CryptoPP::StringSink(plain)
    )
  );

  return plain;
}

std::string sign_rsa(CryptoPP::RSA::PrivateKey SK_CA, std::string message) {
  // rsa signature, do so w/ privatekey 

  CryptoPP::AutoSeededRandomPool rng;
  CryptoPP::RSASSA_PKCS1v15_SHA_Signer signer(SK_CA);
  std::string signature; 

  CryptoPP::StringSource ss1(message, true,
    new CryptoPP::SignerFilter(rng, signer,
      new CryptoPP::StringSink(signature)
    )
  );

  return signature;
}

std::string encrypt_des(std::string key_string, std::string plaintext) {

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

