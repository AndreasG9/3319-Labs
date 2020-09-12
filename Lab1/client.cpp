/*
	Andreas Gagas
	3319 - Wireless Networks and Security
	Lab01 - Implementation and Application of DES
	
	client.cpp 
*/

// PS C:\Dev CS\Wireless Networks and Security\Lab1 

#pragma comment(lib, "Ws2_32.lib")

#include <iostream>
#include <fstream>
#include <string>
#include <winsock2.h>
#include <ws2tcpip.h>

#define DEFAULT_PORT_NUM 8000 
#define BUFFER_LENGTH 512 


int main(int argc, char** argv) {
	
	// ----------- GET KEY -------------------------------------------------------------
	std::string key;
	std::ifstream read_key("key.txt");

	if (read_key.is_open()) {
		while (getline(read_key, key)) {}
		read_key.close();
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
	server.sin_port = htons(DEFAULT_PORT_NUM); // default is 8000

	// Create Socket (client) 
	SOCKET client_socket;

	client_socket = socket(AF_INET, SOCK_STREAM, 0);
	if (client_socket == INVALID_SOCKET) {
		std::cout << "Error, socket creation failed" << std::endl;
		WSACleanup();
		return 1;
	}

	// --------------- Connect to Server -------------------
	retval = connect(client_socket, (struct sockaddr*)&server, sizeof(server));
	if (retval == SOCKET_ERROR) {
		std::cout << "Error, failed to connect" << std::endl;
		closesocket(client_socket);
		WSACleanup();
		return 1;
	}

	std::cout << "Connected" << std::endl; 


	// --------------- Main Loop (Connected to Server) -------------------
	char buffer[BUFFER_LENGTH];
	int retval_send = 0, retval_recieve = 0;
	
	char temp[BUFFER_LENGTH]; 
	
	// SEND init buffer data ... 

	while (true) {
		// recieve and send data to server, until server disconnects

		std::cout << "Type message: "; 

		std::cin.getline(buffer, BUFFER_LENGTH); 
		std::cout << "TEMP. your message is: " << buffer << std::endl; 

		// encrpyt the message 

		std::cout << "This is client." << std::endl; 
		std::cout << ********************<< std::endl;
		std::cout << "Sent plaintext is: " << std::endl; 
		std::cout << "Sent ciphertext is: " << std::endl;
		std::cout << ********************<< std::endl;



	}
	


	

	return 0; 
}