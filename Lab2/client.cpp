/*
  Andreas Gagas
  3319 - Wireless Networks and Security
  Lab02 - Implementation and Application of HMAC ( using SHA-256 )

  client.cpp
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

	// ----------- PORT # -------------------------------------------------------------
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
		while (getline(read_keys, key_hmac_string)) {}
		read_keys.close();
	}

	read_keys.open("key_des.txt", std::ifstream::in);

	if (read_keys.is_open()) {
		// get key des (8 bytes) 
		while (getline(read_keys, key_des_string)) {}
		read_keys.close();
	}

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

	std::cout << "\nConnected" << std::endl << std::endl;


	// --------------- Main Loop (Connected to Server) -------------------
	char message_receive[BUFFER_LENGTH] = { 0 };
	int retval_send = 0, retval_receive = 0;
	//std::string m1, mac, m1_concat_hmac, ciphertext; 
	//std::string encoded_mac, encoded_ct, hash; 

	std::string m1, m2, hmac_received, hmac_calculated, m1_concat_hmac, m2_concat_hmac, ciphertext;
	std::string encoded_mac_received, encoded_mac_calculated, encoded_ct;
	

	// Init keys 
	CryptoPP::SecByteBlock key_hmac((const unsigned char*)(key_hmac_string.data()), key_hmac_string.size());
	CryptoPP::SecByteBlock key_des((const unsigned char*)(key_des_string.data()), key_des_string.size());


	while (true) {
		// recieve and send data to server, until server disconnects

		// get user inputted plaintext 
		m1.clear();
		std::cout << "Type message: ";
		std::getline(std::cin, m1);


		try {
			// HMAC-SHA256(K_HMAC, M1)
			hmac_calculated.clear(); 
			CryptoPP::HMAC< CryptoPP::SHA256 > hmac(key_hmac, key_hmac.size());

			CryptoPP::StringSource (m1, true,
				new CryptoPP::HashFilter(hmac,
					new CryptoPP::StringSink(hmac_calculated)
				)
			);
		}
		catch (const CryptoPP::Exception& err) {
			std::cerr << err.what() << std::endl;
			exit(1);
		}

		// Concatenate plaintext + HMAC, which is: M1 || HMAC(K_HMAC, M1) 
		m1_concat_hmac = m1 + hmac_calculated;

		// DES w/ des_key_string on concat string, which is: DES(K_DES, M1 || HMAC(K_HMAC, M1))  
		try {
			CryptoPP::ECB_Mode< CryptoPP::DES >::Encryption encrypt; // ECB mode       
			encrypt.SetKey(key_des, key_des.size());

			// Encrpyt, add padding if needed 
			ciphertext.clear();
			CryptoPP::StringSource(m1_concat_hmac, true,
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

		// send ciphertext to server/S (as c string) 
		retval_send = send(connected_socket, ciphertext.c_str(), ciphertext.size(), 0);
		if (retval_send == SOCKET_ERROR) {
			std::cout << "Error, failed to send" << std::endl;
			closesocket(connected_socket);
			WSACleanup();
			return 1;
		}


		// Convert mac to readable hex 
		encoded_mac_calculated.clear();
		CryptoPP::StringSource (hmac_calculated, true,
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


		// Client side display (send data)
		std::cout << "\n\nCLIENT SIDE" << std::endl;
		std::cout << "********************" << std::endl;
		std::cout << "Shared HMAC key is: " << key_hmac_string << std::endl;
		std::cout << "Shared DES key is: " << key_des_string << std::endl;
		std::cout << "plain message: " << m1 << std::endl;
		std::cout << "client side HMAC is: " << encoded_mac_calculated << std::endl;
		std::cout << "sent ciphertext is: " << encoded_ct << std::endl;
		std::cout << "********************\n" << std::endl;

		

		std::cout << "\nWaiting to receive a message ... \n" << std::endl;

		while ((retval_receive = recv(connected_socket, message_receive, BUFFER_LENGTH, 0)) > 0) {

			if (retval_receive > 0) {
				// store received ciphertext in c++ string 
				ciphertext.clear();
				ciphertext.append(message_receive, retval_receive);

				try {
					// Decrypt ciphertext using key_des, to get M2 || HMAC(K_HMAC, M2) 

					CryptoPP::ECB_Mode< CryptoPP::DES >::Decryption decrypt;
					decrypt.SetKey(key_des, key_des.size());

					// decrypt, remove padding if needed 
					m2_concat_hmac.clear();
					CryptoPP::StringSource(ciphertext, true,
						new CryptoPP::StreamTransformationFilter(decrypt,
							new CryptoPP::StringSink(m2_concat_hmac)
						)
					);
				}
				catch (const CryptoPP::Exception& err) {
					std::cerr << err.what() << std::endl;
					exit(1);
				}


				// SPLIT m1_concat_hmac to obtain M1 and HMAC(K_HMAC, M1) 
				hmac_received = m2_concat_hmac.substr((m2_concat_hmac.size() - 32), std::string::npos); // USED SHA-256, so the HMAC is the last 256 bits/ 32 bytes 

				// To verify, compute HMAC-SHA256(KEY_HMAC, M1) and compare hash 
				m2 = m2_concat_hmac.substr(0, m2_concat_hmac.size() - 32);

				try {
					// Generate a new HMAC-SHA256(K_HMAC, M1), store in hash_calculated 
					hmac_calculated.clear();
					CryptoPP::HMAC< CryptoPP::SHA256 > hmac(key_hmac, key_hmac.size());

					CryptoPP::StringSource(m2, true,
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

				// Client side display (receive data)
				std::cout << "\n\nCLIENT SIDE" << std::endl;
				std::cout << "********************" << std::endl;
				std::cout << "received ciphertext is: " << encoded_ct << std::endl;
				std::cout << "received plaintext  is: " << m2 << std::endl;
				std::cout << "received hmac is  : " << encoded_mac_received << std::endl;
				std::cout << "calculated hmac is: " << encoded_mac_calculated << std::endl;

				if (hmac_received == hmac_calculated) std::cout << "HMAC Verified" << std::endl;
				else std::cout << "HMAC NOT Verified" << std::endl;

				std::cout << "********************\n" << std::endl;

				break; // client turn to send message, return to main loop 
			}
		}

		if (retval_receive < 0) break; // client disconnected or recv error, break out of main loop 
	}
		

	// server disconnected, cleanup, quit client. 
	shutdown(connected_socket, SD_SEND);
	closesocket(connected_socket);
	WSACleanup();
	std::cout << "Client closed" << std::endl;

	return 0;
}
