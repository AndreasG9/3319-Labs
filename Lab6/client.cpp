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
#define req "memo"

long long int get_epoch_time_seconds();
std::string gen_tmp_key();
std::string encode_hex(std::string ct);
std::string decode_hex(std::string encoded);

std::string encrypt_rsa(CryptoPP::RSA::PublicKey key, std::string plain);
void verifyRSA(CryptoPP::RSA::PublicKey key, std::string signature, std::string msg);

std::string encrypt_des(std::string key_string, std::string plaintext);
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

  std::string IP_C = "127.0.01";
  std::string PORT_C = std::to_string(port_num); 

  //  ===================== GET PUBLIC KEY PK_CA  ===================================================
  // CryptoPP::RSA::PublicKey was encoded and stored in "public_key.txt"
  // Read, decode, and init CryptoPP::RSA::PublicKey to have CA's public key 

  CryptoPP::ByteQueue bytes;
  CryptoPP::FileSource file("public_key.txt", true, new CryptoPP::Base64Decoder);
  file.TransferTo(bytes);
  bytes.MessageEnd();

  CryptoPP::RSA::PublicKey PK_CA;
  PK_CA.Load(bytes);

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

  std::string plaintext, ciphertext, K_TMP2, K_SESS;
  CryptoPP::RSA::PublicKey PK_S;

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
    std::cout << "(C) sent plaintext is: " << plaintext << std::endl << std::endl;
    std::cout << "****************************************************************\n" << std::endl;

    std::cout << "\n(C) Waiting to receive a message from S ... \n" << std::endl;

    // receive step 4 ... PK_S || CERT_S || TS_4
    while ((retval_receive = recv(connected_socket, message_receive, BUFFER_LENGTH, 0)) > 0) {
      if (retval_receive > 0) {
        // store received pt in c++ string 
        plaintext.clear();
        plaintext.append(message_receive, retval_receive);

        // Extract PK_S
        // b/c RSA::PublicKey encoded to c++ string, it size no longer fixed to 1024 bits, it varied, so first 3 bytes will include the size of RSA::PublicKey 
        
        int key_size = std::stoi(plaintext.substr(0, 3));
        std::string public_key_string_encoded = plaintext.substr(3, key_size);

        // Decode HEX
        std::string public_key_string;
        CryptoPP::StringSource(public_key_string_encoded, true,
          new CryptoPP::HexDecoder(
            new CryptoPP::StringSink(public_key_string)
          )
        );

        // Decode key to RSA::PublicKey format
        CryptoPP::StringSource ss(public_key_string, true);
        PK_S.BERDecode(ss);

        // public key's {n, e}
        const CryptoPP::Integer& public_n = PK_S.GetModulus();
        const CryptoPP::Integer& public_e = PK_S.GetPublicExponent();

        // VERIFY CERT_S, using CA's public key
        int current_size = key_size + 3;
        int end_cert_s = plaintext.size() - 10 - 3 - key_size; 

        std::string cert_s_hex_encoded = plaintext.substr(current_size, end_cert_s);
        std::string cert_s = decode_hex(cert_s_hex_encoded);

        // Build msg, to follow CryptoPP signature scheme
        // to verify (msg + signature) 
        std::string msg = ID_S;
        msg += ID_CA;

        std::string encoded_PK_S;
        CryptoPP::StringSink sink(encoded_PK_S);
        PK_S.DEREncode(sink);
        msg += encoded_PK_S;

        verifyRSA(PK_CA, cert_s, msg); // will throw an exception is not verified, (quit the program ) OTHERWISE, PK_S is to be trusted


        // Print received plaintext 
        std::cout << "\n***************************************************************" << std::endl;
        std::cout << "(C) received plaintext (with PK_S and CERT_S HEX encoded): " << plaintext << std::endl << std::endl;
        std::cout << "(C) received plaintext split to display PK_S HEX decoded: \n" << "n: "  << public_n << "\ne: " << public_e << std::endl << std::endl;
        std::cout << "****************************************************************\n" << std::endl;

        break;
      }
    }

    // ========================= STEP 5 ================================
    // build RSA_PK_S[K_TMP_2 || ID_C || IP_C || PORT_C || TS_5]

    K_TMP2 = gen_tmp_key(); // 8-byte K_TMP2

    plaintext = K_TMP2; 
    plaintext += ID_C;
    plaintext += IP_C;
    plaintext += PORT_C;
    plaintext += std::to_string(get_epoch_time_seconds()); // TS_5

    // RSA encrypt w/ PK_S
    ciphertext = encrypt_rsa(PK_S, plaintext);

    do {
      // Prompt user if ready to send msg to S
      std::cout << "Send msg to S (step 5)? hit any key to confirm ...\n";
    } while (std::cin.get() != '\n');

    // send step 5 to S
    retval_send = send(connected_socket, ciphertext.c_str(), ciphertext.size(), 0);
    if (retval_send == SOCKET_ERROR) {
      std::cout << "Error, failed to send" << std::endl;
      closesocket(connected_socket);
      WSACleanup();
      return 1;
    }

    // Print sent ciphertext
    std::cout << "\n***************************************************************" << std::endl;
    std::cout << "(C) sent ciphertext (HEX encoded): " << encode_hex(ciphertext) << std::endl << std::endl;
    std::cout << "(C) generated K_TMP2: " << K_TMP2 << std::endl << std::endl;
    std::cout << "****************************************************************\n" << std::endl;

    // receive step 6 DES_K_TMP2[K_SESS || LIFETIME_SESS || ID_C || TS_6]
    while ((retval_receive = recv(connected_socket, message_receive, BUFFER_LENGTH, 0)) > 0) {

      if (retval_receive > 0) {
        ciphertext.clear();
        ciphertext.append(message_receive, retval_receive);

        // Decrypt using K_TMP2
        plaintext = decrypt_des(K_TMP2, ciphertext);

        K_SESS = plaintext.substr(0, 8);

        // Print received ciphertext and K_SESS
        std::cout << "\n***************************************************************" << std::endl;
        std::cout << "(C) received ciphertext (HEX encoded): " << encode_hex(ciphertext) << std::endl << std::endl;
        std::cout << "(C) received  K_SESS: " << K_SESS << std::endl << std::endl;
        std::cout << "****************************************************************\n" << std::endl;

        break;
      }
    }

    // ========================= STEP 7 ================================
    plaintext = req; // req is "memo"
    plaintext += std::to_string(get_epoch_time_seconds()); // TS_7

    ciphertext = encrypt_des(K_SESS, plaintext);

    do {
      // Prompt user if ready to send msg to S
      std::cout << "Send msg to S (DES_K_SESS[req || TS_7)? hit any key to confirm ...\n";
    } while (std::cin.get() != '\n');

    // send DES_K_SESS[req || TS_7]
    retval_send = send(connected_socket, ciphertext.c_str(), ciphertext.size(), 0);
    if (retval_send == SOCKET_ERROR) {
      std::cout << "Error, failed to send" << std::endl;
      closesocket(connected_socket);
      WSACleanup();
      return 1;
    }

    // Print sent ciphertext
    std::cout << "\n***************************************************************" << std::endl;
    std::cout << "(C) sent ciphertext (HEX encoded): " << encode_hex(ciphertext) << std::endl << std::endl;
    std::cout << "****************************************************************\n" << std::endl;

    // receive DES_K_SESS[data || TS_8]
    while ((retval_receive = recv(connected_socket, message_receive, BUFFER_LENGTH, 0)) > 0) {

      if (retval_receive > 0) {
        ciphertext.clear();
        ciphertext.append(message_receive, retval_receive);

        plaintext = decrypt_des(K_SESS, ciphertext);

        int pt_size = plaintext.size();
        std::string data = plaintext.substr(0, pt_size - 10); // last 10 bytes TS_8

        // Print received ciphertext and data
        std::cout << "\n***************************************************************" << std::endl;
        std::cout << "(C) received ciphertext (HEX encoded): " << encode_hex(ciphertext) << std::endl << std::endl;
        std::cout << "(C) received data message: " <<  data << std::endl << std::endl;
        std::cout << "****************************************************************\n" << std::endl;

        break;
      }
    }
    break; // done
  }
  
  shutdown(connected_socket, SD_SEND);
  closesocket(connected_socket);
  WSACleanup();

  std::cout << "(C) closed" << std::endl;

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

std::string decode_hex(std::string encoded) {

  std::string decoded;

  CryptoPP::StringSource(encoded, true,
    new CryptoPP::HexDecoder(
      new CryptoPP::StringSink(decoded)
    )
  );

  return decoded; 
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

void verifyRSA(CryptoPP::RSA::PublicKey key, std::string signature, std::string msg) {
  // using ca's public key, verify rsa signature

  //RSA signature verification (will throw exception if not-verified)
  CryptoPP::RSASSA_PKCS1v15_SHA_Verifier verifier(key);

  CryptoPP::StringSource ss2(msg + signature, true,
    new CryptoPP::SignatureVerificationFilter(
      verifier, NULL,
      CryptoPP::SignatureVerificationFilter::THROW_EXCEPTION
    )
  );

  std::cout << "\n***************************************************************" << std::endl;
  std::cout << "Verified signature, and therefore PK_S is VALID" << std::endl;
  std::cout << "****************************************************************\n" << std::endl << std::endl;
}