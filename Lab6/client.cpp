/*
  Andreas Gagas
  3319 - Wireless Networks and Security
  Lab06 -Implement PKI-Based Authentication
  client.cpp - this is client
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
#include "cryptopp820/rsa.h"

#define DEFAULT_PORT_NUM 8000 
#define BUFFER_LENGTH 512 

#define ID_CA "ID-CA"
#define ID_C "ID-Client"


int main(int argc, char** argv) {


  return 0; 
}