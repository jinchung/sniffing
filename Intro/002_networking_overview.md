# IP Networking Overview

## Layers, models & architecture

* TCP/IP & OSI
 * OSI model was an attempt at a basis for designing a universal set of network protocols
 * The model should _not_ be taken literally, but can be used as a useful guide in understanding TCP/IP
   1. Physical
   2. Data Link
   3. Network
   4. Transport
   5. Session
   6. Presentation
   7. Application
 * Layers are often named generically by `N` (i.e. "Layer N")
  * e.g. _Protocols_ are Layer-N to Layer-N; _Interfaces_ are Layer-N to Layer-N+1
  * Layer N Protocol Data Unit (PDU) becomes layer N-1 Service Data Unit (SDU)
  * Headers at each layer are prepended to the message
 * TCP/IP
   



