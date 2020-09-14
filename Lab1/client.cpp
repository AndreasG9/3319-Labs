/*
	Andreas Gagas
	3319 - Wireless Networks and Security
	Lab01 - Implementation and Application of DES
	
	client.cpp 
	// PS C:\Dev CS\Wireless Networks and Security\Lab1
*/


#pragma comment(lib, "Ws2_32.lib")
#pragma comment(lib, "cryptlib.lib") 

#include <iostream>
#include <fstream>
#include <string>
#include <winsock2.h>
#include <ws2tcpip.h>

#include "cryptopp820/cryptlib.h"
#include "cryptopp820/des.h"
#include "cryptopp820/osrng.h"
#include "cryptopp820/hex.h"
#include "cryptopp820/secblock.h"
#include "cryptopp820/modes.h" // ECB 
#include "cryptopp820/files.h"


#define DEFAULT_PORT_NUM 8000 
#define BUFFER_LENGTH 512 


int main(int argc, char** argv) {

	// ----------- PORT # -------------------------------------------------------------
	int port_num;

	if (argc == 1) port_num = DEFAULT_PORT_NUM;
	else port_num = sscanf(argv[1], "%d", &port_num);
	
	// ----------- GET KEY, INIT -------------------------------------------------------------
	std::string key_string;
	std::ifstream read_key("key.txt");
	char key_arr[] = "123";

	if (read_key.is_open()) {
		// store in c++ string 
		while (getline(read_key, key_string)) {}
		read_key.close();
	}

	// Init key for use with crypto++ 
	CryptoPP::SecByteBlock key((const unsigned char*)(key_string.data()), key_string.size());


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
	char message_send[BUFFER_LENGTH], message_receive[BUFFER_LENGTH];
	int retval_send = 0, retval_receive = 0;


	std::string encoded, decoded, plaintext, ciphertext;

	while (true) {
		// recieve and send data to server, until server disconnects

		// get user inputted plaintext 
		plaintext.clear();
		std::cout << "Type message: "; 
		std::getline(std::cin, plaintext); 

		try {
			CryptoPP::ECB_Mode< CryptoPP::DES >::Encryption encrypt; // ECB, no init vector needed 
			encrypt.SetKey(key, key.size());

			// Encrpyt, add padding if needed 
			ciphertext.clear();
			CryptoPP::StringSource(plaintext, true,
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
		retval_send = send(connected_socket, ciphertext.c_str(), strlen(ciphertext.c_str())+1, 0);
		if (retval_send == SOCKET_ERROR) {
			std::cout << "Error, failed to send" << std::endl;
			closesocket(connected_socket);
			WSACleanup();
			return 1;
		}

		// Display as HEX
		encoded.clear();
		CryptoPP::StringSource(ciphertext, true,
			new CryptoPP::HexEncoder(
				new CryptoPP::StringSink(encoded)
			)
		);

		// Client side display (send data)
		std::cout << "\n\nHi, this is client." << std::endl; 
		std::cout << "********************" << std::endl;
		std::cout << "key is: " << key_string << std::endl; 
		std::cout << "sent plaintext is: " << plaintext << std::endl; 
		std::cout << "sent ciphertext(hex) is: " << encoded << std::endl;
		std::cout << "********************\n" << std::endl;


		
		// receive ciphertext from server/S 
		retval_receive = recv(connected_socket, message_receive, BUFFER_LENGTH-1, 0);
		if (retval_receive > 0) {


			// convert to c++ string 
			ciphertext.clear();
			ciphertext = message_receive;

			try {
				// DECRYPT

				CryptoPP::ECB_Mode< CryptoPP::DES >::Decryption decrypt;
				decrypt.SetKey(key, key.size());

				// Decrypt, remove padding if needed 
				plaintext.clear();
				CryptoPP::StringSource s(ciphertext, true,
					new CryptoPP::StreamTransformationFilter(decrypt,
						new CryptoPP::StringSink(plaintext)
					)
				);
			}

			catch (const CryptoPP::Exception& err) {
				std::cerr << "ERROR" << err.what() << std::endl;
				exit(1);
			}

			// Display as HEX
			encoded.clear();
			CryptoPP::StringSource(ciphertext, true,
				new CryptoPP::HexEncoder(
					new CryptoPP::StringSink(encoded)
				)
			);


			// Client side display (recieve data)
			std::cout << "\n********************" << std::endl;
			std::cout << "received ciphertext(hex) is: " << encoded << std::endl;
			std::cout << "received plaintext is: " << plaintext << std::endl;
			std::cout << "********************\n" << std::endl;
		}

		else break; // server disconnected or failed to receive, exit loop  
	}
	

	// server disconnected, cleanup, quit client. 
	shutdown(connected_socket, SD_SEND);
	closesocket(connected_socket);
	WSACleanup();
	std::cout << "Client closed" << std::endl;

	return 0; 
}