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

	char key_arr[9];
	strcpy(key_arr, key.c_str()); // convert to c string 



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

	while (true) {
		// recieve and send data to server, until server disconnects

		std::cout << "Type message: "; 
		std::cin.getline(message_send, BUFFER_LENGTH);

		// encrpyt the message ...

		// send ciphertext to server/S 
		retval_send = send(connected_socket, message_send, strlen(message_send)+1, 0);
		if (retval_send == SOCKET_ERROR) {
			std::cout << "Error, failed to send" << std::endl;
			closesocket(connected_socket);
			WSACleanup();
			return 1;
		}

		// Client side display (send data)
		std::cout << "\n\nHi, this is client." << std::endl; 
		std::cout << "********************" << std::endl;
		std::cout << "key is: " << key_arr << std::endl; 
		std::cout << "sent plaintext is: " << message_send << std::endl; 
		//std::cout << "sent ciphertext is: " << std::endl;
		std::cout << "********************\n" << std::endl;

		
		// receive ciphertext from server/S 
		retval_receive = recv(connected_socket, message_receive, BUFFER_LENGTH-1, 0);
		if (retval_receive > 0) {
			// DECRYPT ... 

			// Client side display (recieve data)
			std::cout << "\n********************" << std::endl;
			std::cout << "received ciphertext is: " << message_receive << std::endl;
			//std::cout << "received plaintext is: " << std::endl;
			std::cout << "********************\n" << std::endl;
		}

		else if (retval_receive == 0) break; // server disconnected 

		else {
			std::cout << "Error, receive failed" << std::endl;
			closesocket(connected_socket);
			WSACleanup();
			exit(1);
		}
		 
		
		//memset(message_send, 0, BUFFER_LENGTH); 
	}
	
	// server disconnected, cleanup, quit client. 
	shutdown(connected_socket, SD_SEND);
	closesocket(connected_socket);
	WSACleanup();
	std::cout << "Client closed" << std::endl;

	return 0; 
}