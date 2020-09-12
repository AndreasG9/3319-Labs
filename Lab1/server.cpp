/*
  Andreas Gagas
  3319 - Wireless Networks and Security 
  Lab01 - Implementation and Application of DES 

  server.cpp
*/

#pragma comment(lib, "Ws2_32.lib")

#include <iostream>
#include <fstream>
#include <string>
#include <winsock2.h>
#include <ws2tcpip.h>

#define DEFAULT_PORT_NUM 8000 
#define BUFFER_LENGTH 512 


int main(int argc, char **argv) {

  // ----------- PORT # -------------------------------------------------------------
  int port_num; 

  if (argc == 1) port_num = DEFAULT_PORT_NUM;
  else port_num = sscanf(argv[1], "%d", &port_num); 

  // ----------- GET KEY -------------------------------------------------------------
  std::string key;
  std::ifstream read_key("key.txt");

  if (read_key.is_open()) {
    while (getline(read_key, key)) {}
    read_key.close();
  }

  //std::cout << "key is: " << key << std::endl;



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

  std::cout << "Connected" << std::endl; 
  closesocket(server_socket); 

   // ----------- Main Loop (Client is connected) ---------------------------------------------- 
  char buffer[BUFFER_LENGTH]; 
  int retval_send = 0, retval_recieve = 0;


  while (true) {
    // recieve and send data to client, until client disconnects


    // client will send an encrypted message/ chiphertext, store in buffer 
    retval_recieve = recv(client_socket, buffer, BUFFER_LENGTH, 0); 
    if (retval_recieve > 0) {
      // good data, decrypt message 

      retval_send = send(client_socket, buffer, retval_recieve, 0);
      if (retval_send == SOCKET_ERROR) {
        closesocket(client_socket);
        WSACleanup();
        return 1; 
      }

      else {
        // successfully sent 
      }
    }

    else if (retval_recieve == 0) break; // client disconnected, exit loop

    else {
      std::cout << "Error, recv function failed, socket error" << std::endl;
      closesocket(client_socket);
      WSACleanup();
      exit(1); 
    }

  }

  shutdown(client_socket, SD_SEND);
  closesocket(client_socket); 
  WSACleanup(); 
  std::cout << "Server closed" << std::endl; 

  return 0; 
}