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

#include "cryptopp820/sha.h"

