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

#define ID_C "CIS3319USERID"
#define ID_TGS "CIS3319TGSID"
#define ID_V "CIS3319SERVERID"
#define LIFETIME_2 60
#define LIFETIME_4 86400


std::string decrypt(std::string key_string, std::string ciphertext);
std::string encrypt(std::string key_string, std::string plaintext);
long long int get_epoch_time_seconds(); 
std::string gen_session_key(); 

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

  // Get keys (AS access to K_C, TGS access to K_TGS, TGS (and V) has access to K_V) 
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
  int retval_send = 0, retval_receive = 0;

  std::string encoded, plaintext, ciphertext, user, key_c_tgs, ticket, ticket_tgs;

  // ----------- Main Loop ( Client(C) is connected to Server1(AS && TGS) ---------------------------------------------- 

  while (true) {
    // recieve and send data to client, until client disconnects

    std::cout << "\n(AS) waiting to receive client info ... \n" << std::endl;

    // client will send info to AS
    while ((retval_receive = recv(client_socket, message_receive, BUFFER_LENGTH, 0)) > 0) {

      if (retval_receive > 0) {
        user.clear();
        user.append(message_receive, retval_receive);

        // AS side display (receive user info msg) 
        std::cout << "\n***************************************************************" << std::endl;
        std::cout << "(AS) received message is: " << user << std::endl;
        std::cout << "****************************************************************\n" << std::endl;

        // ======================= STEP (2)=======================================================
        // SPLIT string to get ID_C (already hardcoded, dont really need to do it) 
        std::string id_c = user.substr(0, strlen(ID_C));

        // AS will generate K_C_TGS (session key), size will be 8-bytes
        key_c_tgs = gen_session_key();

        // Ticket_TGS = E(K_TGS, [K_C_TGS || ID_C || AD_C || ID_TGS || TS_2 || LIFETIME_2) 
        std::string TS_2 = std::to_string(get_epoch_time_seconds());
        ticket = key_c_tgs + id_c + AD_C + ID_TGS + TS_2 + std::to_string(LIFETIME_2);

        // Encrypt ticket using DES with key_tgs to get ticket_tgs
        ticket_tgs = encrypt(key_tgs_string, ticket);

        // msg concatenation 
        plaintext.clear();
        plaintext += key_c_tgs;
        plaintext += ID_TGS;
        plaintext += TS_2;
        plaintext += std::to_string(LIFETIME_2);
        plaintext += ticket_tgs;

        // E(K_C, [K_C_TGS || ID_C ||AD_C || ID_TGS || TS_2 || Lifetime_2]) using DES with K_C 
        ciphertext.clear();
        ciphertext = encrypt(key_c_string, plaintext);

        // SEND ENCRYPTED MSG (Shared session key, encrypted ticket + other info) to client
        retval_send = send(client_socket, ciphertext.c_str(), ciphertext.size(), 0);
        if (retval_send == SOCKET_ERROR) {
          closesocket(client_socket);
          WSACleanup();
          return 1;
        }

        break; // TGS will take over  
      }
    }

    if (retval_receive <= 0) break; // this server will close once client disconnects (leave early, or connect to new server V) 

    std::cout << "\n(TGS) waiting to receive client info ... \n" << std::endl;

    // TICKET-GRANTING SERVER (TGS), receive ID_V || TICKET_TGS || AUTH_C 
    while ((retval_receive = recv(client_socket, message_receive, BUFFER_LENGTH, 0)) > 0) {
        
      if (retval_receive > 0) {
        user.clear();
        user.append(message_receive, retval_receive);

        // TGS CHECK to see if ticket is VALID (compare (current - TS_2) < Lifetime_2) 
        // first extract Ticket_tgs (for formality, we are "TGS" now, assume ticket_tgs same size as it should be when AS send its msg)
        int start = strlen(ID_V);
        std::string ticket_tgs_extracted = user.substr(start, ticket_tgs.size()); 
        int ticket_tgs_padding = ticket_tgs_extracted.size(); // use to get auth_c a few lines down

        ticket_tgs_extracted = decrypt(key_tgs_string, ticket_tgs_extracted);
        std::cout << ticket_tgs_extracted << std::endl; 
        start = key_c_tgs.size() + strlen(ID_C) + AD_C.size() + strlen(ID_TGS);
        int TS_2_extracted = std::stoi(ticket_tgs_extracted.substr(start, 10));

        int current_t = get_epoch_time_seconds(); 
        int valid = current_t - TS_2_extracted;
        std::string validity = valid < LIFETIME_2 ? "true" : "false"; 
        
        // decrypt auth_c to print msg clearly 
        start = strlen(ID_V) + ticket_tgs_padding;
        std::string auth_c = user.substr(start);
        auth_c = decrypt(key_c_tgs, auth_c);
        
        // assemble the receive msg back together
        std::string user_msg = user.substr(0, strlen(ID_V)); 
        user_msg += ticket_tgs_extracted; 
        user_msg += auth_c; 

        int size_idv = strlen(ID_V); 

        // (TGS) Print received msg and validitry of Ticket_tgs
        std::cout << "\n***************************************************************" << std::endl;
        std::cout << "(TGS) received message (after decrypt Auth_c): " << user_msg << std::endl; 
        std::cout << "(TGS) split ID_V: " << user_msg.substr(0, size_idv) << std::endl; 
        std::cout << "(TGS) split Ticket_tgs (decrypted in TGS): " << user_msg.substr(size_idv, ticket_tgs_extracted.size()) <<std::endl;
        std::cout << "(TGS) split Auth_c: " << user_msg.substr(size_idv + ticket_tgs_extracted.size()) << std::endl;
        std::cout << "(TGS) valid message (current_t - TS_2 = " << valid << ") < 60: "<< validity << std::endl;
        std::cout << "***************************************************************\n" << std::endl; 

        if (validity == "false") {
          // ticket time expired, exit loops 
          std::cout << "INVALID TICKET" << std::endl;
          break; 
        }

        // ======================= STEP (4) =======================================================
        // E(K_C_TGS[K_C_V || ID_V || TS_4 || TICKET_V])

        long long int TS_4 = get_epoch_time_seconds(); 
        std::string key_c_v = gen_session_key(); // new session key for C and V generated by TGS

        // Ticket_V formation E(K_V[K_C_V || ID_C || AD_C || ID_V || TS_4 || LIFETIME_4]) 
        std::string ticket_v; 
        ticket_v += key_c_v;
        ticket_v += ID_C;
        ticket_v += AD_C; 
        ticket_v += ID_V; 
        ticket_v += std::to_string(TS_4);
        ticket_v += std::to_string(LIFETIME_4); 
        ticket_v = encrypt(key_v_string, ticket_v); 

        // Display ciphertext as HEX
        std::string encoded;
        CryptoPP::StringSource(ticket_v, true,
          new CryptoPP::HexEncoder(
            new CryptoPP::StringSink(encoded)
          )
        );

        std::cout << "TICKET V HEX:" << encoded << std::endl; 


        std::string tgs_msg;
        tgs_msg += key_c_v; 
        tgs_msg += ID_V;
        tgs_msg += std::to_string(TS_4);
        tgs_msg += ticket_v;
        tgs_msg = encrypt(key_c_tgs, tgs_msg); 

        // Send ENCRYPTED tgs_msg to C
        retval_send = send(client_socket, tgs_msg.c_str(), tgs_msg.size(), 0);
        if (retval_send == SOCKET_ERROR) {
          closesocket(client_socket);
          WSACleanup();
          return 1;
        }

        // AS AND TGS WORK IS COMPLETE (server2.cpp will take over as V)
        // WILL REVERT TO START OF AS LOOP or quit if client disconnects
        break;
      }
    }

    if (retval_receive <= 0) break; // this server will close once client disconnects (leave early, or connect to new server V) 
  }

  // client disconnected, cleanup, quit server. 
  shutdown(client_socket, SD_SEND);
  closesocket(client_socket);
  WSACleanup();
  std::cout << "Server (AS/TGS) closed (client disconnected)" << std::endl;

	return 0;
}


long long int get_epoch_time_seconds() {
  // get time stamp (epoch equivalent) 

  long long int time = std::chrono::duration_cast<std::chrono::seconds>(std::chrono::system_clock::now().time_since_epoch()).count();

  return time; 
}

std::string gen_session_key() {
  // return string (8-byte long) random chars, this will be out session key generated by AS 

  std::string chars = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";
  srand(time(0));
  std::string temp;

  for (int i = 0; i < 8; ++i) {
    temp += chars[rand() % chars.size()];
  }

  return temp;
}

std::string encrypt(std::string key_string, std::string plaintext) {

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