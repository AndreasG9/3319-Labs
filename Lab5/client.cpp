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

		// Get keys 
		std::string key_c, key_tgs, key_v;
		std::ifstream read_keys("keys.txt");

		if (read_keys.is_open()) {
			getline(read_keys, key_c);
			getline(read_keys, key_tgs);
			getline(read_keys, key_v);
		}

		read_keys.close();

		std::cout << key_c << "\n" << key_tgs << "\n" << key_v << std::endl;

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

		std::string encoded, decoded, plaintext, ciphertext;

		while (true) {

			do {
				// Prompt user if ready to send user info msg to AS
				std::cout << "Send msg to AS (CIS3319USERIDCIS3319TGSID || time stamp) ? hit any key to confirm ...\n";
			} while (std::cin.get() != '\n'); 

			// info msg to send to AS 
			plaintext.clear();
			plaintext += ID_C;
			plaintext += ID_TGS;
			plaintext += std::to_string(get_epoch_time_seconds()); 

			std::cout << "I am going to send: " << plaintext << std::endl; // REMOVE 

			// Send auth info to AS 
			retval_send = send(connected_socket, plaintext.c_str(), plaintext.size(), 0);
			if (retval_send == SOCKET_ERROR) {
				std::cout << "Error, failed to send" << std::endl;
				closesocket(connected_socket);
				WSACleanup();
				return 1;
			}

			std::cout << "\nWaiting to receive a message from AS ... \n" << std::endl;





		}




  return 0; 
}

	long long int get_epoch_time_seconds() {
		// get time stamp (epoch equivalent) 

		long long int time = std::chrono::duration_cast<std::chrono::seconds>(std::chrono::system_clock::now().time_since_epoch()).count();

		return time;
	}