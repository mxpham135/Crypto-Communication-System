# Crypto-Communication-System
Demonstrate a secure communication system between two parties using cryptography. The program is split into two parts; a sender and a receiver. A sender **(sender.java)** would encrypt the data and save the information into a text file **transmitted-data.txt**. A receiver **(receiver.java)** would decrypt and authenticate the data from **transmitted-data.txt** to read the original message. 

## Optional
It is not required to run **generatedKeys.java** in order to test the sender and receiver programs. However, to see how the RSA pair key and MAC shared key are produced, this program should be run before the sender and receiver programs. This program would generate the three text files **rsaPublicKey.txt, rsaPrivateKey.txt, and macSharedKey.txt** that the sender and receiver use.

## HOW TO USE THE PROGRAM
The program is set up for simplistic use which does not require any additional input data or information.
1. Download and go to the directory that content all files (java and text)
2. **(Optional)** Run `generatedKeys.java`
3. Run `sender.java`
4. Run `receiver.java`




