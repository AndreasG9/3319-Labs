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

		// Get keys 
		std::string key_c_string, ignore, ignore2;
		std::ifstream read_keys("keys.txt");

		if (read_keys.is_open()) {
			getline(read_keys, key_c_string);
			getline(read_keys, ignore); // TGS KEY, CLIENT DOESN'T HAVE ACCESS, so ignore
			getline(read_keys, ignore2); // V KEY, CLIENT DOESN'T HAVE ACCESS, so ignore
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

		std::string encoded, plaintext, ciphertext, ticket_v, auth_c, key_c_v, TS_4; // use a bunch of other string var, declare inside loop 

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

				// DECRYPT msg to get session key, encrypted ticket, plus other info
				plaintext.clear();
				plaintext = decrypt(key_c_string, ciphertext); // plaintext will contain K_C_TGS || ID_TGS || TS_2 || LIFETIME_2 || encrypted TICKET_TGS

				// SPLIT plaintext string to get K_C_TGS (session_key from AS)
				std::string k_c_tgs = plaintext.substr(0, 8); // the session key I generated in AS (server1.cpp) is 8-bytes

				// SPLIT to get TICKET_tgs (client doesn't have access to key_tgs to decrypt) 
				int lifetime_2_size = std::to_string(LIFETIME_2).size(); 
				int start = 8 + strlen(ID_TGS) + 10 + lifetime_2_size; 
				std::string ticket_tgs = plaintext.substr(start);

				// Display ticket_tgs as HEX
				encoded.clear();
				CryptoPP::StringSource(ticket_tgs, true,
					new CryptoPP::HexEncoder(
						new CryptoPP::StringSink(encoded)
					)
				);


				// Print received plaintext and ticket from AS
				std::cout << "\n***************************************************************" << std::endl;
				std::cout << "(C) received plaintext is: " << plaintext << std::endl << std::endl;;
				std::cout << "(C) received Ticket_tgs is: " << ticket_tgs << std::endl << std::endl;;
				std::cout << "(C) received Ticket_tgs (HEX encoded) is: " << encoded << std::endl;
				std::cout << "****************************************************************\n" << std::endl;


				// ============================ (3) ============================================
				// Generate Authenticator_C = E(K_C_TGS, [ID_C, AD_C, TS_3])
				auth_c = ID_C; 
				auth_c += AD_C;
				auth_c += std::to_string(get_epoch_time_seconds()); // TS_3
				auth_c = encrypt(k_c_tgs, auth_c); // encrypt using session key just extracted 

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

						// decrypt and split msg, to get key_c_v
						plaintext.clear();
						plaintext = decrypt(k_c_tgs, ciphertext);
						key_c_v = plaintext.substr(0, 8);

						// save ticket_v (still encrypted) 
						int start = 8 + strlen(ID_V) + 10;
						ticket_v = plaintext.substr(start); 


						// Display Ticket_v as HEX
						encoded.clear();
						CryptoPP::StringSource(ticket_v, true,
							new CryptoPP::HexEncoder(
								new CryptoPP::StringSink(encoded)
							)
						);



						// Print received plaintext and ticket from TGS
						std::cout << "\n***************************************************************" << std::endl;
						std::cout << "(C) received plaintext is: " << plaintext << std::endl << std::endl;
						std::cout << "(C) received Ticket_v is: " << plaintext.substr(start) << std::endl << std::endl;
						std::cout << "(C) received Ticket_v (HEX encoded) is: " << encoded << std::endl;
						std::cout << "****************************************************************\n" << std::endl;

						break; 
					}
				}
				break; 
			}
			break; 
		}



		// close old socket 
		shutdown(connected_socket, SD_SEND);
		closesocket(connected_socket);

		// CONNECT TO V (server2.cpp)
		server.sin_port = htons(8001); // V 
		SOCKET connected_socket2;

		connected_socket2 = socket(AF_INET, SOCK_STREAM, 0);
		if (connected_socket2 == INVALID_SOCKET) {
			std::cout << "Error, socket creation failed" << std::endl;
			WSACleanup();
			return 1;
		}

		retval = connect(connected_socket2, (struct sockaddr*)&server, sizeof(server));
		if (retval == SOCKET_ERROR) {
			std::cout << "Error, failed to connect" << std::endl;
			closesocket(connected_socket2);
			WSACleanup();
			return 1;
		}

		std::cout << "\nConnected to V" << std::endl << std::endl;

		do {
			// Prompt user if ready to send msg to service V
			std::cout << "Send msg to V (Ticket_v || Auth_c)? hit any key to confirm ...\n";
		} while (std::cin.get() != '\n');


		// build new auth_c (new time stamp TS_5 at end)
		auth_c = ID_C + AD_C + std::to_string(get_epoch_time_seconds());
		auth_c = encrypt(key_c_v, auth_c);

		// build msg using same ticket_v we received (still encrypted), and new auth_c
		plaintext = ticket_v + auth_c; 


		//  SEND TICKET_V || AUTH_C to V (server2.cpp)  
		retval_send = send(connected_socket, plaintext.c_str(), plaintext.size(), 0);
		if (retval_send == SOCKET_ERROR) {
			std::cout << "Error, failed to send" << std::endl;
			closesocket(connected_socket);
			WSACleanup();
			return 1;
		}

		// Receive E(K_C_V[TS_5 + 1]) from V (server2.cpp)
		while ((retval_receive = recv(connected_socket, message_receive, BUFFER_LENGTH, 0)) > 0) {

			if (retval_receive > 0) {
				// store received data in c++ string 
				ciphertext.clear();
				ciphertext.append(message_receive, retval_receive);
			}

			// Decrypt using K_C_V
			plaintext = decrypt(key_c_v, ciphertext);


			// Print received plaintext from V
			std::cout << "\n***************************************************************" << std::endl;
			std::cout << "(C) received plaintext is (TS_5 + 1): " << plaintext << std::endl;
			std::cout << "*****************************************************************\n" << std::endl;

			break; 
		}

		do {
			// server v will now provides requested services .... 
			std::cout << "Quit? hit any key to confirm ...\n";
		} while (std::cin.get() != '\n');

		shutdown(connected_socket2, SD_SEND);
		closesocket(connected_socket2);
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