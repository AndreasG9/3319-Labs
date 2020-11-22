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
#define BUFFER_LENGTH 1024 

#define ID_CA "ID-CA"
#define ID_S "ID-Server"
#define LIFETIME_SESS 86400

long long int get_epoch_time_seconds(); 
std::string gen_tmp_key();
std::string encode_hex(std::string ct); 

std::string encrypt_rsa(CryptoPP::RSA::PublicKey key, std::string plain);
std::string decrypt_rsa(CryptoPP::RSA::PrivateKey key, CryptoPP::AutoSeededRandomPool rng, std::string cipher);

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

  std::string plaintext, ciphertext, CERT_S; 
  CryptoPP::RSA::PrivateKey SK_S;
  CryptoPP::RSA::PublicKey PK_S;


  while (true) {

    //  ===================== STEP 1, Register w/ CA ===================================================
  
    std::string temp_des = gen_tmp_key(); 

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


    // Print out sent ciphertext and temp des key
    std::cout << "\n***************************************************************" << std::endl;
    std::cout << "(S) sent ciphertext (HEX encoded): " << encode_hex(ciphertext) << std::endl;
    std::cout << "(S) generated K_TMP1: " << temp_des << std::endl;
    std::cout << "***************************************************************\n" << std::endl;

    // if retval receive <=0

    std::cout << "\n(S) Waiting to receive a message from CA ... \n" << std::endl;

    while ((retval_receive = recv(connected_socket, message_receive, BUFFER_LENGTH, 0)) > 0) {

      if (retval_receive > 0) {
        ciphertext.clear();
        ciphertext.append(message_receive, retval_receive);


        // Decrypt ct using K_tmp1 to get bunch of info .. including cert, and our public/private key pair
        plaintext = decrypt_des(temp_des, ciphertext);

        
        // Extract PK_S (using 1024 RSA::PublicKey/RSA::PrviateKey sizes, but encoded to be sent as c++ strings, so exact size tricky
        // but the first three bytes will contain the size of the one key (and same for next key) 
        // encoded, each key will then  be between 630-634 bytes or somewhere between there, but will differ each time execute as different keys generated)
        int key_length = std::stoi(plaintext.substr(0, 3));
        int current = key_length + 3;
        CryptoPP::StringSource ss(plaintext.substr(3, key_length), true);
        PK_S.BERDecode(ss); // Decode key (currently string), to get RSA::PublicKey for S 

        // Extract SK_S
        key_length = std::stoi(plaintext.substr(current, 3));
        current += 3;
        current += key_length; 
        int start = 3 + std::stoi(plaintext.substr(0, 3)) + 3;
        CryptoPP::StringSource ss2(plaintext.substr(start, key_length), true);
        SK_S.BERDecode(ss2); // Decode key (currently string), to get RSA::PrivateKey for S 

        // Extract Cert_S
        key_length = std::stoi(plaintext.substr(current, 3));
        current += 3; 
        CERT_S = plaintext.substr(current, key_length); 
      
        // public key's {n, e}
        const CryptoPP::Integer& public_n = PK_S.GetModulus();
        const CryptoPP::Integer& public_e = PK_S.GetPublicExponent();

        // private key's {n, d} 
        const CryptoPP::Integer& private_n = SK_S.GetModulus();
        const CryptoPP::Integer& private_d = SK_S.GetPrivateExponent();

        // Print recieved key pair and Cert_s
        std::cout << "\n***************************************************************" << std::endl;
        std::cout << "(S) received ciphertext (HEX encoded): " << encode_hex(ciphertext) << std::endl;
        std::cout << "(S) received Public Key PK_S: " << "\nn:" << public_n << "\ne: " << public_e << std::endl;
        std::cout << "(S) received Private Key SK_S: " << "\nn:" << private_n << "\nd: " << private_d << std::endl;
        std::cout << "(S) Cert_s (HEX encoded): " << encode_hex(CERT_S) << std::endl;
        std::cout << "***************************************************************\n" << std::endl;
      }
      break; 
    }
    break; 
  }


  // close old socket


  // CONNECT to C (client.cpp)


  while (true) {

    // receive ID || TS3
    

    // Extract TS_4

    // =========================== STEP 4 ==========================
    //plaintext.clear();
    //plaintext += PK_S;
    //plaintext += CERT_S;
    //plaintext += "TS_4";

    // send plaintext message 

    // receive RSA_PK_S[K_TMP_2 || ID_C || IP_C || PORT_C || TS_%]

    // Extract K_TMP2



    break; 
  }

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