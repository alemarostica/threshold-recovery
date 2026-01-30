# Threshold Wallet Recovery with Verifiable Secret Sharing and Server-Aided Access Control
## Description of the Scenario
The project implements a controlled recovery mechanism for private keys based on a **Threshold Signature Scheme** (**TSS**). The goal is to prevent the permanent loss of funds without ever reconstructing the private key at a single point of vulnerability, ensuring that recovery is only possible in the event of a lack of user activity. The private key is not simply saved, but distributed via a **Verifiable Secret Sharing** (**VSS**) algorithm among n participants and a Recovery Server. Thanks to VSS, each participant can mathematically verify the integrity of their share without knowing the original secret.
## Activation mechanism
The system monitors the user's liveness. Recovery can only begin if: 
- **Inactivity**: The user does not provide signed proof of activity for a predefined period of time. 
- **Time Expiration**: A predefined expiration date T is reached. 
Once the inactivity condition is met the server unlocks its participation capacity. The protocol is initialized and the collaboration between the server and the k−1 shareholders allows operations on the wallet without the private key ever being exposed or completely recomposed.
## Some notes
- Project uses POSIX filemode, they techincally work on Windows as Go translates them to NTFS's ACL, but on a more complete implementation we should cover the Windows case
