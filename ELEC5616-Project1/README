Welcome to SkyNet
=================



Usage: Peer to Peer (Echo)
(Note: Requires two bots at the same time)
==========================
smerity@pegasus:~/usyd/elec5616_proj/framework$ python3.2 bot.py
Listening on port 1337
Waiting for connection...
Enter command: p2p echo
Finding another bot...
Shared hash: 6b86b273ff34fce19d6b804eff5a3f5747ada4eaa22f1d49c01e52ddb7875b4b
Found bot on port 1338

Original message : b'ECHO'
Encrypted data: b'.\xc5\xfa<'
Sending packet of length: 4

Echo> Test

Original message : b'Test'
Encrypted data: b'?\xe3\xc1\x07'
Sending packet of length: 4


Receiving message of length: 4
Encrypted data: b'?\xe3\xc1\x07'
Original message: b'Test'

Echo> echo

Original message : b'echo'
Encrypted data: b'\x0e\xe5\xda\x1c'
Sending packet of length: 4


Receiving message of length: 4
Encrypted data: b'\x0e\xe5\xda\x1c'
Original message: b'echo'

Echo> exit

Original message : b'exit'
Encrypted data: b'\x0e\xfe\xdb\x07'
Sending packet of length: 4


Receiving message of length: 4
Encrypted data: b'\x0e\xfe\xdb\x07'
Original message: b'exit'


Notice: 'Test' and 'exit' are sent and received as the same encrypted message.
This means it's vulnerable to frequency analysis. When 'a' is sent multiple times,
it ends up "looping" as we're using a simple repeated XOR cypher.
This is something that should be fixed.
