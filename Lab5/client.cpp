/*
  Andreas Gagas
  3319 - Wireless Networks and Security
  Lab05 - Implementation and Application of Kerberos

  client.cpp - client C
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
#include "cryptopp820/osrng.h"
#include "cryptopp820/hex.h"
#include "cryptopp820/secblock.h"
#include "cryptopp820/modes.h"

#include "cryptopp820/des.h"

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


	int main(int argc, char** argv) {

		// ----------- PORT # -------------------------------------------------------------
		int port_num;

		if (argc == 1) port_num = DEFAULT_PORT_NUM;
		else port_num = atoi(argv[1]);

		if (argc > 2) {
			std::cout << "Too many args, include the port num or nothing";
			exit(1);
		}

		std::string AD_C = "127.0.01:" + std::to_string(port_num);

		// Get keys ( K_C, K_tgs, K_V) 
		std::string key_c_string, key_tgs_string, key_v_string;
		std::ifstream read_keys("keys.txt");

		if (read_keys.is_open()) {
			getline(read_keys, key_c_string);
			getline(read_keys, key_tgs_string);
			getline(read_keys, key_v_string);
		}

		read_keys.close();

		// ----------- Network Setup (Winsock) ----------------------------------------------

		// similar to what we did with server.cpp ... 
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

		// --------------- Connect to Server -------------------
		retval = connect(connected_socket, (struct sockaddr*)&server, sizeof(server));
		if (retval == SOCKET_ERROR) {
			std::cout << "Error, failed to connect" << std::endl;
			closesocket(connected_socket);
			WSACleanup();
			return 1;
		}

		std::cout << "\nConnected to AS" << std::endl << std::endl;

		char message_receive[BUFFER_LENGTH] = { 0 };
		int retval_send = 0, retval_receive = 0;

		std::string encoded, decoded, plaintext, ciphertext, ticket_v, auth_c;

		while (true) {

			do {
				// Prompt user if ready to send user info msg to AS
				std::cout << "Send msg to AS (CIS3319USERIDCIS3319TGSID || time stamp)? hit any key to confirm ...\n";
			} while (std::cin.get() != '\n'); 

			// info msg to send to AS 
			plaintext.clear();
			plaintext += ID_C;
			plaintext += ID_TGS;
			plaintext += std::to_string(get_epoch_time_seconds()); 

			// Send auth info to AS 
			retval_send = send(connected_socket, plaintext.c_str(), plaintext.size(), 0);
			if (retval_send == SOCKET_ERROR) {
				std::cout << "Error, failed to send" << std::endl;
				closesocket(connected_socket);
				WSACleanup();
				return 1;
			}

			std::cout << "\n(C) Waiting to receive a message from AS ... \n" << std::endl;

			while ((retval_receive = recv(connected_socket, message_receive, BUFFER_LENGTH, 0)) > 0) {

				if (retval_receive > 0) {
					// store received data in c++ string 
					ciphertext.clear();
					ciphertext.append(message_receive, retval_receive);
				}

				// DECRYPT msg to get session key, ticket, plus other info
				plaintext.clear();
				plaintext = decrypt(key_c_string, ciphertext); // plaintext will contain K_C_TGS || ID_TGS || TS_2 || LIFETIME_2 || TICKET_TGS

				// SPLIT plaintext string to get TICKET_tgs (K_C_TGS will always be an 8-byte string, epoch time in string is 10-bytes, LIFETIME_2 will be 2-bytes)
				int lifetime_2_size = std::to_string(LIFETIME_2).size(); 
				int start = 8 + strlen(ID_TGS) + 10 + lifetime_2_size; 
				std::string ticket_ciphertext = plaintext.substr(start); // will return encrypted TICKET_TGS
				
				// SPLIT plaintext string to get K_C_TGS (session_key from AS)
				std::string k_c_tgs;
				k_c_tgs = plaintext.substr(0, 8); 

				// DECRYPT TICKET_TGS with K_TGS 
				std::string ticket_tgs = decrypt(key_tgs_string, ticket_ciphertext); 


				// Print received plaintext and ticket from AS
				std::cout << "\n***************************************************************" << std::endl;
				std::cout << "(C) received plaintext is (ticket_tgs decrypted next line): " << plaintext << std::endl; // in this plaintext string ticket_tgs was still encrypted
				std::cout << "(C) received Ticket_tgs is: " << ticket_tgs << std::endl; 
				std::cout << "*****************************************************************\n" << std::endl;

				// ============================ (3) ============================================
				// Generate Authenticator_C = E(K_C_TGS, [ID_C, AD_C, TS_3])
				auth_c = ID_C; 
				auth_c += AD_C;
				auth_c += std::to_string(get_epoch_time_seconds()); // TS_3
				auth_c = encrypt(k_c_tgs, auth_c); 

				// SEND ID_V || TICKET_TGS || AUTH_C to Ticket-granting server (still AS) 
				plaintext.clear();
				plaintext += ID_V; 
				plaintext += ticket_tgs;
				plaintext += auth_c;


				do {
					// Prompt user if ready to send user info msg to TGS
					std::cout << "Send msg to TGS (ID_V || TICKET_TGS || AUTH_C)? hit any key to confirm ...\n";
				} while (std::cin.get() != '\n');

				retval_send = send(connected_socket, plaintext.c_str(), plaintext.size(), 0);
				if (retval_send == SOCKET_ERROR) {
					std::cout << "Error, failed to send" << std::endl;
					closesocket(connected_socket);
					WSACleanup();
					return 1;
				}


				// ============================ (5) ============================================ 
				// receive  E(K_C_TGS[K_C_V || ID_V || TS_4 || TICKET_V]) from TGS

				while ((retval_receive = recv(connected_socket, message_receive, BUFFER_LENGTH, 0)) > 0) {

					if (retval_receive > 0) {
						// store received ciphertext in c++ string 
						ciphertext.clear();
						ciphertext.append(message_receive, retval_receive);

						// decrypt and split msg, to get encrypted ticket_v, decrypt to get plaintext of ticket_v
						plaintext.clear();
						plaintext = decrypt(k_c_tgs, ciphertext);

						int start = 8 + strlen(ID_V) + 10; // 8 for TGS session key, length of ID_V, and 10 bytes for time string. 
						ticket_v = plaintext.substr(start); 
						ticket_v = decrypt(key_v_string, ticket_v); 

						// Print received plaintext and ticket from TGS
						std::cout << "\n***************************************************************" << std::endl;
						std::cout << "(C) received plaintext is: " << plaintext << std::endl;
						std::cout << "(C) received Ticket_v is: " << ticket_v << std::endl;
						std::cout << "*****************************************************************\n" << std::endl;

						break; 
					}
				}
				break; 
			}
			break; 
			//if (retval_receive < 0) break; 
		}

		std::cout << "WILL NOW CONNECT TO SERVER V!" << std::endl; 
		std::cin.get();

		// server disconnected, cleanup, quit client. 
		shutdown(connected_socket, SD_SEND);
		closesocket(connected_socket);

		// CONNECT TO V/SERVICE (server2.cpp)
		server.sin_port = htons(8001); // V 

		retval = connect(connected_socket, (struct sockaddr*)&server, sizeof(server));
		if (retval == SOCKET_ERROR) {
			std::cout << "Error, failed to connect" << std::endl;
			closesocket(connected_socket);
			WSACleanup();
			return 1;
		}

		std::cout << "\nConnected to V" << std::endl << std::endl;


		// SEND TICKET_V || AUTH_C to V (server2.cpp) 

		do {
			// Prompt user if ready to send msg to service V
			std::cout << "Send msg to V (Ticket_v || Auth_c)? hit any key to confirm ...\n";
		} while (std::cin.get() != '\n');



		// Receive E(K_C_V[TS_5 + 1]) from V (server2.cpp)


		// Decrypt using K_C_V

		// Print received plaintext and ticket from TGS
		std::cout << "\n***************************************************************" << std::endl;
		std::cout << "(C) received plaintext is: " << "todo" << std::endl;
		std::cout << "(C) received Ticket_tgs is: " << "todo" << std::endl;
		std::cout << "*****************************************************************\n" << std::endl;

		shutdown(connected_socket, SD_SEND);
		closesocket(connected_socket);
		WSACleanup();
		std::cout << "Client (C) closed" << std::endl;
		return 0; 
}

	long long int get_epoch_time_seconds() {
		// get time stamp (epoch equivalent) 

		long long int time = std::chrono::duration_cast<std::chrono::seconds>(std::chrono::system_clock::now().time_since_epoch()).count();

		return time;
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