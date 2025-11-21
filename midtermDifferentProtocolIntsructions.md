# Protocol Overview
To prevent unauthorized access to remote areas, a control system is designeed, where users unlock electronic locks with their NFC-capable phones. Since such locks have constrained processing capabilities (slow CPU, limited power and memory), they are unable to perform asymmetruc cryptographic operations. To alleviate this, you*ll implement a version of Leslie Lamport's one-time-password scheme that is based on one-way hash functions. We'll ve working wiht SHA256. The entire procedure roughly consists of three steps_

1. In the first step, the user generates a chain of tokens (hashes) and securely uploads the last token in the chain to the company security server. In practice, such transmission would occur over a secured TCP/IP socket. The user would upload a new token when existing tokens would run out; typically once or twice a year. The details of token generation are provided below.
2. In the second step the security server transfers tokens to electronic locks. This transmission is performed via an out-of-band channel; imagine tokens being transmitted through a serial protocol by a technician that is physically next to the lock. However, in order to store the tokens, the technician must authenticate herself and this is achieved with the help of a password-based MAC scheme whose details are specified below. Typically, such procedure would be performed once per month.
3. In the third step, as user tries to gain lock access by using her NFC-capable phone. When standing next to the door, she places her phone next to the lock and the phone transmits a token over the NFC link. The electronic lock then verifies the token using the Lamport's procedure described below.

To further simplify the example, we assume the company uses only one electronic lock and there is only one user that is allowed to open it. (In general, one would have to generate different tokens for different locks and keep tokens between users separate, but you do not have to handle such cases.)

## Token generation
1. User chooses a secret s.
2. She then repeatedly applies the hash funciton SHA256 to the secret s, giving a value of SHA256(SHA256(...SHA256(s)...)).
3. The final value, denoted as SHA256^1000(s), is then securely transmitted to the security server and the latter then transmits it to the electronic lock. The lock stores this value.

## Token verification
1. When trying to open the lock, the user places her phone next to the lock and a token is transmitted. If we generated 1000 tokens, we would transmit token t=SHA256^999(s) when opening the lock for the first time.
2. The electronic lock would then apply another round of SHA256 to the received token t and then compare the result to the stored value. In the case of first access, the stored value would be the token the user uploaded to the security Server: SHA256^1000(s).
3. If the computed value and the stored value match, the access is granted and the currently stored value is replaced with token t. Otherwise access is rejected.

The token verification is run every time a user attempts to open the electronc lock. Note that the user has to submit a different token for each access. Thus for the next access, the user would usse a token that is obtained by hashing the initial secret 998 times. The user can repeat this until she runs out of tokens. At that time, she has to generate a new secret, compute new tokens and upload them to the security server.

## The programming assignment
We have three agenets: a user Alice, a security Server and an electronic Lock; and three communication channels.
### Mutually authenticate channel Alice-Server and generate a shared secret
Authenticate the channel between Alice and Server. They both use RSA public-private key pairs and their public keys are known to both of them: Alice knows Servers' and Server knows Alices'. Your task is to mutually authenticate the peers and generate a shared secret: Alice needs to be sure she is talking to the Server and vice-versa. Define the public-secret key pairs globally in the main method.

Implement the key-agreement and key negotiation in a manner that is forward-secure: so even if the adversary was to record all message exchanges between Alice and the Server and then later would manage to steal their key-pairs (secret keys in particular), he still would be unable to decrypt the recorded messages.

You may decide to skip this step and assume that Alice and Server already have a shared symmetric secret. But in this case, you will not be awarded points for this assignment.

### Provide symmetric confidentiality and integrity and produce token
Use symmetric cryptographic primitives negotiated above to provide confidentiality and integrity to the communication channel Alice-Server. Then as Alice, implement the procedure that generates 1000 tokens and upload the last token in the chain to the security Server over the secured channel.
Implement the following auxiliary function hash and use it in the protocol.

### Transfer the token from Server to Lock
Then as the Server, forward that token to the Lock. When forwarding the token, the Server must compute the MAC tag and send it alongside the token, otherwise the Lock will reject it. The tag is computed with HMAC-SHA256, while the key is derived from a shared password that is known to Server and the Lock; you may define that password globally in the main method. As the password-based key-derivation function use PBKDF2 with HMAC-SHA256 and set the iteration counter to 1000. Thus when forwarding the token, the Server must also send the tag and the salt that is used to verify the tag.

Lock should receive the token from Server, and verify it. If the verifcation succeeds, the token is stored to a local variable. Implement the auxiliary functions mac and verify and use them in the protocol.

### Implement the token-based access-control in Lock
Alice tries to open the lock by sending a token. Lock verifies the received token and if the verification succeeds, the Lock prints SUCCESS and otherwise it prints FAILURE.