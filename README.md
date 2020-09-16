
### Basic Python UDP Server. 
##### It simply parses and verifies packets. This script, however, does not fully follow the conventional UDP packet structure. 

```4 Bytes Packet ID
4 Bytes Packet Sequence
2 Bytes Mulitbyte Repeating XOR Key
2 Bytes # of Checksums
(Variable) Repeating key XOR Key
...
...
...
64 bytes 512-byte RSA Signature
```
