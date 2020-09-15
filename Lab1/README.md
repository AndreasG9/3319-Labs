# Lab1: Implementation and Application of DES  - Andreas Gagas
## Development 
**Language**: C++ 
**OS:** Windows 10
**IDE**: visual studio 2019 for windows. developed **without** project model, compiled seperate .cpp files with MSVC on command line. 
**Command Line:** cl.exe filename.cpp /EHsc /MT  (flags for multi-threading for lib, and c++ exceptions) 
**External Library** Crypto++ 8.2.0. I included the build and lib file in the source folder, but setting up the STATIC library is relatively easy 

   (**HOW TO INCLUDE LIBRARY, IF NEEDED**). 
- Download Crypto++ 8.2.0 and extract ... 
- Open crypttest.sln or cryptlib.vcxproj in Visual Studio. Build -> Batch Build -> SELECT cryptlib Release Win32 -> **BUILD**.
- Copy the cryptlib.lib (in cryptopp820 -> win32 -> Output -> Release -> cryptlib.lib) in same folder as .cpp files (server.cpp and client.cpp). 
- Because of my header declarations, make sure the entire cryptopp820 folder and cryptlib.lib are in the same folder with .cpp files.  
- folder will include server.cpp, client.cpp, cryptopp820, cryptlib.lib
- use command line listed above to compile both .cpp files with MSVC 


**How to run**: To reiterate, you have **key.txt, server.cpp, client.cpp, cryptopp820,** and **cryptlib.lib**. 
- Tools -> Command Line -> Developer Powershell 
- cl.exe server.cpp /EHsc /MT
- cl.exe client.cpp /EHsc /MT
- Open a second powershell in that folder 
- **run the server first:**     ./server
- **run the client second:** ./client 
- .. started communcation 



**Other:** Optionally you can provide a port num as an arg (./server 8001), just make sure you do it for both programs. If not, it defaults to port 8000. The key in key.txt is just a string of 8 chars/8 bytes. Also, there is a buffer length with sending a message(512), if you send a very long message you will get an error. 

I included a video that shows compilation, and the running of the server and client. 