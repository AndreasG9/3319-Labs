# Lab 2: Implementation and Application of HMAC - Andreas Gagas 

**Language:** C++
**OS**: Windows 10
**IDE**: Visual Studio 2019, but developed without project mode, compiled separate .cpp 
files with MSVC on command line. 
**External Libraries**: Crypto++ 8.2.0, built as static library (cryptlib Release Win32) 
<br/>
**How to include library, if needed**
* Download Crypto++ 8.2.0 and extract ...  [crypto++ download page](https://www.cryptopp.com/index.html#download)
* Open crypttest.sln or cryptlib.vcxproj in Visual Studio. Build -> Batch Build -> SELECT cryptlib Release Win32 ->  **BUILD**.
* Copy the cryptlib.lib (in cryptopp820 -> win32 -> Output -> Release -> cryptlib.lib) in same folder as .cpp files (server.cpp and client.cpp).
-   Because of my header declarations, make sure the entire cryptopp820 folder and cryptlib.lib are in the same folder with .cpp files.
-   Folder will include **server.cpp, client.cpp, cryptopp820, cryptlib.lib, key_des.txt, key_hmac.txt**
 
**How to include run**
- (x2)  Tools -> Command Line -> Developer Powershell
-   cl.exe server.cpp /EHsc /MT
-   cl.exe client.cpp /EHsc /MT
-   **run the server first:**  ./server
-   **run the client second:**  ./client
-   .. started communication

**Other:** video included that shows compilation, and the running of the server and client. 
**Repository**: https://github.com/AndreasG9/3319-Labs/tree/master/Lab2