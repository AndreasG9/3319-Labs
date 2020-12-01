# Lab : Implement PKI_Based Authentication

**Language:** C++
**OS**: Windows 10 
**IDE**: Visual Studio 2019, but developed without project mode, compiled separate .cpp 
files with MSVC on command line.
**External Libraries**: Crypto++ 8.2.0, built as static library (cryptlib Release Win32) <br/>
**How to include library, if needed**
* Download Crypto++ 8.2.0 and extract ...  [crypto++ download page](https://www.cryptopp.com/index.html#download)
* Open crypttest.sln or cryptlib.vcxproj in Visual Studio. Build -> Batch Build -> SELECT cryptlib Release Win32 ->  **BUILD**.
* Copy the cryptlib.lib (in cryptopp820 -> win32 -> Output -> Release -> cryptlib.lib) in same folder as .cpp files (keys.txt, server1.cpp, server2.cpp and client.cpp).
-   Because of my header declarations, make sure the entire cryptopp820 folder and cryptlib.lib are in the same folder with .cpp files.
-   Folder will include **ca.cpp, server.cpp client.cpp, cryptopp820, cryptlib.lib**
 
**How to run**
- (x3)  Tools -> Command Line -> Developer Powershell
-   cl.exe ca.cpp /EHsc /MT
- cl.exe server.cpp /EHsc /MT
-   cl.exe client.cpp /EHsc /MT
-   **run  ca first:**  ./ca  &nbsp;&nbsp;&nbsp;&nbsp; 
-  **run server second  :**  ./server &nbsp;&nbsp;&nbsp;&nbsp;
- **ONCE CONNECTED HIT ENTER ON SERVER SIDE TO REGISTER SERVER, TO GET KEY/PAIR**
-   **run the client AFTER registration (server will say (S) waiting for incoming connection on port: 8000:**  ./client &nbsp;&nbsp;&nbsp;&nbsp; 
-   .. started communication (note client sending its msg is **not automated**, will prompt you to hit any key to send step3/5/7.
- .. the RSA signature verification for CERT_S (and therefore PK_S) shouldn't fail, but will thrown an exception and close the client side if signature could not be verified.

**Other:** video included that shows compilation, and the running of the ca, server and client. <br/> 
**Repository**: https://github.com/AndreasG9/3319-Labs/tree/master/Lab6

Note: CERT_S is hex encoded for visibility. RSA::PublicKey and RSA::PrivateKey instances are encoded to c++ strings, then hex encoded for visibility. But  when side has access, I convert the keys back to RSA::Public/PrivateKey and print {n, e} or {n, d}, for visibility purposes (to show the keys were properly sent and received) 

Also to NOTE: The only extra addition I did was add the key size of the sent key/s as explained above, they are no longer fixed to 1024 bits when convert CryptoPP::Public/PrivateKey to c++ string (later HEX encoded for visibility). B/c the size of the string could vary slightly each run, this was the only compromise to allow me use CryptoPP's RSA key generation, storage, verification, etc ...   