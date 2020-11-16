# Lab 5: Implementation and Application of Kerberos

**Language:** C++ <br/>
**OS**: Windows 10 <br/>
**IDE**: Visual Studio 2019, but developed without project mode, compiled separate .cpp <br/>
files with MSVC on command line. <br/>
**External Libraries**: Crypto++ 8.2.0, built as static library (cryptlib Release Win32) <br/>
<br/>
**How to include library, if needed**
* Download Crypto++ 8.2.0 and extract ...  [crypto++ download page](https://www.cryptopp.com/index.html#download)
* Open crypttest.sln or cryptlib.vcxproj in Visual Studio. Build -> Batch Build -> SELECT cryptlib Release Win32 ->  **BUILD**.
* Copy the cryptlib.lib (in cryptopp820 -> win32 -> Output -> Release -> cryptlib.lib) in same folder as .cpp files (keys.txt, server1.cpp, server2.cpp and client.cpp).
-   Because of my header declarations, make sure the entire cryptopp820 folder and cryptlib.lib are in the same folder with .cpp files.
-   Folder will include **server1.cpp, server2.cpp client.cpp, cryptopp820, cryptlib.lib, keys.txt**
 
**How to run**
- (x3)  Tools -> Command Line -> Developer Powershell
-   cl.exe server1.cpp /EHsc /MT
- cl.exe server2.cpp /EHsc /MT
-   cl.exe client.cpp /EHsc /MT
-   **run  server1 first:**  ./server1  &nbsp;&nbsp;&nbsp;&nbsp; <-- This is (AS/TGS)
-  **run server2  :**  ./server2 &nbsp;&nbsp;&nbsp;&nbsp;<-- This is (V)
-   **run the client second:**  ./client &nbsp;&nbsp;&nbsp;&nbsp;<-- This is (C)
-   .. started communication (note client sending its msg is **not automated**, will prompt you to hit any key to send step1/step3/step5, was done this way to show if you wait 60+ seconds before sending step 3, the tgs ticket will be invalid and error will show). 

**Other:** video included that shows compilation, and the running of the servers and client. <br/> 
**Repository**: https://github.com/AndreasG9/3319-Labs/tree/master/Lab5