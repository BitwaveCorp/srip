# Secure Remittance Information Protocol

## Introduction

This specification defines a **secure remittance information protocol** for attaching structured payment information to blockchain and potentially non-blockchain transactions. It supports both on-chain data **embeds** and off-chain **references** to ISO 20022 remittance advice documents. The goal is to enable rich remittance information (e.g. invoice details, payment context) to accompany crypto-asset transfers across networks like Ethereum (and EVM-compatible chains), Stellar, and Ripple XRP Ledger, facilitating automated reconciliation in line with ISO 20022 standards. In ISO 20022 payment messaging, a payment can either carry detailed remittance info or provide a *remittance location reference* for out-of-band advice. This protocol mirrors that approach: the on-chain message may contain a small encrypted remittance payload or a pointer to an external ISO 20022 document, using a consistent format with versioning and security features.

**Key features:**

* **Versioned Magic Prefix:** Each message begins with a magic byte and version number to identify the protocol and allow future upgrades.
* **Conditional Payload:** The message indicates if it contains an embedded encrypted remittance advice (for short data like invoice ID, amounts) or a URI pointer to an off-chain ISO 20022 document (for full structured remittance details).
* **Hashed Key Identifier:** To enable recipients to efficiently detect relevant messages, a hashed (salted) Key ID is included. This is derived from a shared secret key, but does not reveal the key itself. Recipients use it to filter incoming transactions for those intended for them.
* **End-to-end Security:** All on-chain payloads are encrypted with a symmetric key shared between sender and recipient, and off-chain documents are digitally signed (e.g. via HMAC) with the same key material. This ensures confidentiality and authenticity—only the intended recipient can decrypt the data, and any off-chain document’s origin can be verified by the recipient.
* **Multi-network Support:** The specification provides encoding and implementation guidelines for Ethereum/EVM (using event logs), Stellar (using transaction memos and data entries), and Ripple XRP Ledger (using transaction Memos). Each network’s native transaction fields are leveraged to carry the remittance message without modifying base protocols.

By adhering to this specification, implementers can attach ISO 20022-compliant remittance information to blockchain payments in a secure, interoperable way. Rich payment data (invoice numbers, dates, references, etc.) can travel with cross-border crypto payments, improving reconciliation while preserving privacy and efficiency. The following sections describe the message format, metadata, URI handling, network-specific guidelines, and security considerations in detail.

## 1. Message Encoding Structure (Versioning and Encryption Model)

Each remittance message is encoded as a binary payload with a fixed header and a conditional body. The encoding is network-agnostic – it can be stored in an Ethereum log, a Stellar memo, an XRP Ledger memo, etc. The structure is as follows (in order):

* **Magic Byte (1 byte):** A constant prefix (e.g. `0xA5`) identifying this protocol. This magic value distinguishes the remittance message from arbitrary data and helps detect the presence of protocol data. It also signals that the next byte is a version. (Using a magic prefix is a common technique to recognize custom on-chain data.)

* **Version (1 byte):** The protocol version number, allowing the format to evolve over time. Version `0x01` is the initial version defined in this specification. Changes to the message format or cryptographic schemes will increment this version. A parser should check this byte and choose the appropriate decoding logic.

* **Flags (1 byte):** A bit-field indicating the payload type and encryption scheme. In version 1, the primary flag of interest is the *payload mode*:

    * `0x00` = **Embedded Payload Mode** – the message contains a small encrypted remittance data blob within the on-chain payload.
    * `0x01` = **URI Pointer Mode** – the message contains a URI pointer to an off-chain remittance document (with associated signature).
      Future flag bits could signal alternate encryption algorithms or formats. Unrecognized flags must be ignored or cause the message to be treated as incompatible with this version.

* **Salt (8 bytes):** A random salt value used in computing the Key ID hash (next field). This salt is generated anew for each message. It prevents two transactions with the same secret key from having identical Key ID hashes, enhancing privacy by thwarting correlation. The salt is included in plaintext as part of the message so that the recipient knows its value for hash recomputation. (Eight bytes provides \~2^64 salt space, effectively eliminating collisions; smaller or larger sizes MAY be used in future versions.)

* **Hashed Key ID (32 bytes):** A cryptographic hash of the shared secret key (known to sender and intended recipient), combined with the above salt. For example, `KeyID = SHA-256(salt || secretKey)`. This serves as an **identifier for the encryption key** used. The Key ID hash lets the receiver detect if a transaction is meant for them by comparing it against hashes of keys they hold, without revealing the actual key. It is analogous to using a reference or account number in a memo for filtering. The hash should be computed with a preimage-resistant function (SHA-256 in version 1) and can be truncated (e.g. to 16 bytes) if space is constrained, though 32 bytes is recommended to avoid collisions. The Key ID hash **MUST** be verified by the recipient before attempting decryption (i.e. the recipient computes SHA-256 of salt plus each candidate key to see if it matches the message’s Key ID). If no match, the message is not for that recipient.

* **Encrypted Remittance Payload (variable length, optional):** Present if *Embedded Payload Mode* is indicated. This field contains a small piece of remittance information (such as an invoice or bill reference, payment amount, etc.), encrypted with the shared secret key. The encryption uses an authenticated symmetric cipher – for example, **AES-256-GCM** in version 1 (256-bit key, 96-bit IV, 128-bit authentication tag). The field is composed of:

    * an **IV (initialization vector)** for the cipher (e.g. 12 bytes for AES-GCM),
    * the **ciphertext** of the remittance data, and
    * an **authentication tag** (e.g. 16 bytes) for integrity.
      The exact lengths depend on the cipher; for AES-GCM the overhead is 28 bytes (IV + tag) plus ciphertext length. The total encrypted payload is intended to be small (tens of bytes). For example, an invoice number and amount could be encoded in \~20 bytes before encryption; after encryption overhead, \~50–60 bytes might be stored on-chain. This fits comfortably in event logs or memos. Only the intended recipient (with the secret key) can decrypt this field. The AEAD encryption provides confidentiality and authenticity – if the ciphertext or tag is modified, the recipient’s decryption will fail authentication.

* **URI Pointer (variable length, optional):** Present if *URI Pointer Mode* is indicated. Instead of an embedded invoice, the message carries a reference to an external document:

    * **URI Length (1 byte)** – length of the URI that follows (if more than 255 bytes needed, the protocol could use 2 bytes in a future version, but in v1 URIs up to 255 bytes are supported).
    * **URI String (variable)** – the URI pointing to the off-chain remittance document. This is typically an ASCII text string (UTF-8 encoded) giving a web link or other resource locator. For example, it could be an HTTPS URL to an ISO 20022 XML file, or another scheme as defined in Section 3 (e.g. `https://example.com/remittance/INV-1001.xml`). The URI should be as short as possible to minimize on-chain storage (consider using compact domains or query strings if needed). The URI **may be encrypted** with the shared key for additional privacy (in version 1, the URI is by default stored in plaintext for simplicity, but implementations MAY encrypt it similarly to the embedded payload, especially if the URI itself might reveal sensitive info about the parties or invoice).
    * **File Hash (variable, option)

* **Document Signature/Digest (fixed length):** In *URI Pointer Mode*, following the URI, the message includes a cryptographic digest that allows the recipient to verify the authenticity of the off-chain document. This is typically an **HMAC-SHA256** computed over the contents of the ISO 20022 document using the shared secret key (32 bytes output) or a similar keyed signature. The inclusion of this field ties the external document to the on-chain transaction: when the receiver fetches the document from the given URI, they can compute the HMAC with their key and compare it to this on-chain value to confirm the document is exactly what the sender intended and hasn’t been tampered with. Only someone with the shared key could have generated the correct HMAC, so this serves as a signature. (Alternatively, the sender could sign the document using an asymmetric key and include a signature blob or the document’s hash on-chain. However, to keep the design unified, we use the same symmetric key for verification in v1.)

**Figure: Message Byte Layout (Version 1)** – *Magic* (1 byte) | *Version* (1 byte) | *Flags* (1 byte) | *Salt* (8 bytes) | *KeyID Hash* (32 bytes) | *Encrypted Payload* (IV + data + tag, if flags=0x00) … OR … *URI Length* (1 byte, if flags=0x01) | *URI String* (n bytes) | *Document HMAC* (32 bytes).

This structure is inserted into the on-chain transaction in a manner specific to each network (see Section 4). The magic byte and version at the start ensure any parser or system can recognize and route these messages appropriately even as the protocol evolves. The encryption model is symmetric-key (shared secret) encryption for confidentiality, combined with authentication tags or hashes for integrity. The use of a hashed key identifier with a salt allows the *recipient* to efficiently scan for relevant remittance messages without exposing the key or a static identifier to the public blockchain (which could link multiple transactions). In summary, the message format is compact and self-contained, enabling secure transmission of reference data alongside a payment.

## 2. Protocol Metadata: Key IDs, Salts, and Signatures

This section defines the metadata and cryptographic schemes that underpin the protocol: the Key ID scheme for message filtering, the derivation of encryption keys and signatures, and the structure of signatures for validation.

### 2.1 Shared Key and Key ID Scheme

**Shared Secret Key:** The protocol assumes that each pair of transacting parties (payer and payee) share a secret key ahead of time. This could be established out-of-band (e.g. exchanged through a secure channel or derived via a Diffie-Hellman key exchange between the parties’ public keys). The key is used symmetrically: the sender uses it to encrypt the remittance data (or sign the document), and the receiver uses the same key to decrypt and verify. The key should be high-entropy (256-bit recommended) and unique per relationship (or even per invoice, if one-time keys are preferred). It **must** be kept confidential to the two parties.

**Hashed Key ID:** To avoid exposing the identity or raw key on-chain, the protocol uses a *hashed key identifier*. As described in Section 1, the Key ID is computed by hashing the secret key with a salt: `KeyIDHash = H(salt || key)`. This hash (32 bytes in v1) is included in the on-chain message. Its purpose is to let the intended recipient recognize that a given transaction is for them, by matching the hash. The recipient will iterate through the set of secret keys they maintain (each shared with a different potential sender) and compute the hash with the given salt for each; if one matches the KeyIDHash from the message, they’ve found the correct key to use for decryption. This design allows **filtering**: the recipient’s wallet or back-end system can scan blockchain events and quickly discard those whose KeyIDHash doesn’t match any known value, focusing only on relevant remittance messages. The use of a salt ensures that even if the same key is used in multiple transactions, the KeyIDHash appears different each time, preventing observers from linking those transactions by a common identifier. In other words, the salt provides *non-repeatability*. (If static Key IDs without salt were used, anyone watching could notice the same hash on two payments and infer they likely involve the same parties – which is a privacy leak. Salting avoids this at the cost of requiring per-message computation by the receiver rather than simple subscription filtering.)

**Salt Handling:** The salt is included in plaintext in the message, as it doesn’t need to be secret – its role is to randomize the Key ID hash. The salt **MUST** be generated uniformly randomly for each message (version 1). Eight bytes is sufficient to prevent collisions or precomputation; even if an attacker tried to guess the key by precomputing hashes of common keys, the random salt makes the hash different for each payment. The salt can also double as a message-specific identifier if needed (since it’s unique per message with high probability). Recipients must use the exact salt provided when recomputing the KeyIDHash. Senders should never reuse the same salt with the same key (i.e. do not send two messages in a row with identical salt value and key).

**Key Derivation (Encryption & Signature):** The shared secret key is used for both encryption and for generating integrity signatures (HMAC). To avoid any possibility of reusing the same key bits for two different cryptographic purposes, it is RECOMMENDED to derive sub-keys from the shared secret: e.g. use an HKDF (HMAC-based Key Derivation Function) to derive an **encryption key** and a **MAC key** from the shared secret. For instance, one could use the salt or protocol constant as HKDF info/context to derive two 256-bit keys – one for AES-GCM encryption, one for computing the HMAC for the document. In practice, for simplicity, implementations MAY use the raw shared key directly for both AES-GCM and HMAC in v1 (since both are symmetric and 256-bit), but separating the key material is a good security practice (avoiding any theoretical cross-protocol weaknesses). The versioning mechanism can accommodate introducing a formal KDF in future versions.

The hashed Key ID itself does not need a separate key; it is produced from the same shared secret (with salt). Optionally, the hash function could be an HMAC as well (using the key to hash itself with salt), but a standard hash like SHA-256 is sufficient here (the key is secret, and salt prevents rainbow-table attacks on keys if someone tried to brute force by hashing candidate keys).

### 2.2 Encryption Model and Payload Encoding

For on-chain *embedded* remittance data, the protocol uses symmetric authenticated encryption. In version 1, the recommended algorithm is **AES-256-GCM** (AES in Galois/Counter Mode with 256-bit key). AES-GCM provides confidentiality and built-in integrity via its authentication tag. The sender must generate a unique random IV (nonce) for each encryption operation (12 bytes for GCM) – this IV is included in the message so the receiver can use it to decrypt. The plaintext for the encryption is the remittance information (e.g. a structured string or binary containing things like an invoice number, date, amount, reference text, etc.). The encrypted payload field (as described in Section 1) includes `[IV | Ciphertext | AuthTag]`. The **AuthTag** (authentication tag) is typically 16 bytes and is computed over the ciphertext (and optionally header data – in our case, one could include the KeyIDHash or other fields as additional authenticated data for extra binding, though in v1 this isn’t strictly required). The receiver, upon finding a KeyID match, will use the derived encryption key to attempt AES-GCM decryption. If the tag verification fails, the message is invalid or was tampered with (or an attacker used a wrong key). A failed decryption MUST be treated as “not for this key” – the recipient should then either try the next key or discard the message if no key produces a valid decrypt.

The encrypted payload is designed to be **small** – only minimal critical data that the receiver needs immediately is meant to go here (such as an invoice or bill identifier, a payment description code, etc.). By keeping this payload under, say, 64 bytes before encryption (\~100 bytes after encryption overhead), we minimize on-chain footprint. This makes it feasible to include in cost-sensitive environments (for example, writing \~100 bytes to an Ethereum log is on the order of a few thousand gas). If more than a trivial amount of data needs to be conveyed, the pointer mode should be used instead.

#### 2.2.1 Invoice Record payload

While we expect a large number of different payloads, we've proposed a single standardized invoice record payload, defined as a protobuf message for easy handling. First, to signal the payload type, we're including a magic byte of "I" at the beginning. Then, we flow into a

**Figure: Invoice Record Payload Layout (Version 1)** - *Tag* (1 byte, “0x49” - “I”) | *Protobuf Encoded Message* (n bytes)

```
message InvoiceRecord {
  string  invoice_id = 1
  optional org_id = 2
}
```


### 2.3 Off-Chain Document Signature

For *URI Pointer Mode*, the off-chain remittance advice (the actual detailed document, likely an ISO 20022 XML file such as a stand-alone Remittance Advice message `remt.001`) must be signed or accompanied by a digest to ensure authenticity. The protocol uses the shared secret key to generate this signature, ensuring the same trust basis as the on-chain encryption. In v1, we use an **HMAC-SHA256** (keyed hash) over the entire document content:

* The sender computes `HMAC_SHA256(key, document_contents)` which yields a 32-byte tag.
* This tag is then included in the on-chain message (the *Document HMAC* field after the URI).

When the receiver obtains the document from the given URI, they compute the HMAC with their copy of the key and verify it matches the on-chain value. If it matches, the document is confirmed to be exactly what the sender intended (untampered) and indeed issued by someone with knowledge of the shared key (presumably the payer). If it does not match, the document must be considered untrustworthy or corrupted.

The signature (HMAC) binds the off-chain data to the on-chain transaction. This is crucial because a URI alone is not immutable – for example, an HTTPS URL might point to a server that could be compromised or the content changed. The blockchain record of the HMAC prevents undetected changes: even if an attacker intercepted the URL and served a fake document, they would not have the key to forge a matching HMAC. The recipient will detect the mismatch and reject the document.

It’s worth noting that including the HMAC on-chain is functionally similar to including a hash of the document, except that it’s keyed (secret). One benefit of a public hash (without a key) would be that third parties could verify that the content at the URI hasn’t changed. However, here we specifically want the verification tied to the secret key for authenticity, not just integrity, since the recipient might be the only one authorized to view/verify the document. The HMAC serves both purposes for the recipient. (If desired, future versions could include an *additional* public digest of the document for transparency or audit reasons, but that is optional and not in v1.)

**Signature Format:** The HMAC is stored as raw 32 bytes in the message. It is not encoded in any higher-level format (to save space). The off-chain document itself can also include a signature or reference if needed. For example, an ISO 20022 XML could include an extension element carrying the HMAC or a digital signature. This is not mandated by the protocol, since the on-chain inclusion is sufficient for the recipient’s needs. The protocol simply requires that the document **MUST be signed** (or an HMAC provided) using the same key, and that this signature be made available to the recipient (our approach being to include it in the on-chain payload).

**Linking Payments to Documents:** In practice, the off-chain ISO 20022 remittance document will often contain its own identifier and possibly reference the payment. ISO 20022 provides a *Remittance Identifier* (`RmtId`) data element specifically to link a stand-alone remittance advice to a payment. Implementers should consider using the Key ID (or a derivative) as the Remittance Identifier in the ISO message, or include the transaction hash/reference in the document, so that there is a clear two-way linkage. This goes beyond the on-chain protocol but is a good practice: the on-chain transaction carries a pointer to the document, and the document carries an ID that ties back to the payment, enabling auditors or backend systems to correlate them.

In summary, the protocol metadata ensures that for each remittance message:

* There is a secure key lookup (via hashed ID),
* The encryption uses a known algorithm with a shared secret,
* The off-chain data is authenticated with a keyed signature,
* And all pieces (salt, key hash, signature) are packaged so the recipient can verify integrity and origin before using the information.

## 3. URI-Based Payload Handling

When the remittance information is too large or complex to embed on-chain, the protocol uses a URI reference to an off-chain document. This section details how URI pointers are handled, including supported URI schemes, validation requirements, and encoding considerations.

### 3.1 Supported URI Schemes

The protocol is designed to be flexible in referencing external data. In version 1, the primary expected scheme is **`https://`** (HTTPS URLs), given its ubiquity and built-in transport security. HTTPS allows the document to be hosted on a web server accessible to the recipient. The use of HTTPS (as opposed to http) is **strongly recommended** to ensure encryption in transit and server authentication when fetching the document.

Other URI schemes MAY be supported as needed, especially those common in financial networks. For example:

* **`sftp://` or `ftps://`** – for documents available via secure FTP servers.
* **`ipfs://`** or content-addressable URIs – for documents stored on decentralized storage (IPFS, Arweave, etc.). In such cases, the content hash in the URI provides integrity, but an HMAC is still required for authenticity.
* **Financial network URIs:** If a particular banking network has a standardized URI scheme for referencing documents (for instance, a SWIFT FileAct reference or an internal bank API endpoint), those could be used. There isn’t a widely adopted URI scheme for ISO 20022 message retrieval as of now, but the implementer can treat those as custom HTTPS endpoints or other schemes as appropriate.
* **`urn:` URIs or other identifiers** – potentially a URN that a particular ecosystem understands (e.g. a URN that a bank’s system can resolve to a document).

In all cases, the URI scheme and format should be agreed upon by the parties or the ecosystem using the protocol. The protocol itself doesn’t limit the scheme, but both sender and receiver must have a way to actually retrieve the document from that URI. If a scheme is not recognized or supported by the receiver’s system, the remittance info cannot be fetched (so such usage would be an out-of-spec custom extension).

By default, and for interoperability, **HTTPS** is the baseline scheme. This covers common web hosting of remittance advice (e.g. a company hosting invoice details at a URL), and it leverages existing internet infrastructure.

### 3.2 URI Encoding in On-Chain Message

The URI pointer is placed in the on-chain message as described in Section 1: a 1-byte length followed by the URI string bytes. The length is the number of bytes (characters) in the URI. The URI is stored as raw text (UTF-8 encoding). No additional encoding (like base64) is applied, since the memo/log itself can handle binary data. On networks where the memo field is text-only (e.g., Stellar’s MEMO\_TEXT is defined as UTF-8 string), the URI should be a valid UTF-8 string – which standard ASCII URLs are. Care should be taken that the URI length does not exceed what can be stored in the given network’s field (Section 4 covers specific limits).

If the URI is particularly long (close to 255 bytes), the one-byte length in this version could overflow. In practice, we expect remittance advice URLs to be reasonably short (a few tens of bytes up to perhaps 100 bytes). If needed, future versions can extend the length field to 2 bytes to allow very long URIs. Alternatively, a long URI could be made shorter by using a redirect service or a short alias code (though that introduces dependency on the availability of that service).

**Example URI encoding:** Suppose the off-chain document is available at `https://payments.examplebank.com/remit/2025-06/INV-12345.xml`. This is 60 characters long. In the message, it would be encoded as: `0x3C` (60 in hex) followed by the UTF-8 bytes of the URL string. The recipient will read the length, then extract that many bytes as the URI.

Optionally, as noted earlier, the URI itself can be encrypted for privacy. If URI encryption is enabled (which could be indicated by a flag bit), the URI bytes stored are not plaintext but cipher text (likely using the same key and an IV). In such a scenario, the receiver would first decrypt the URI field to obtain the true URI, then proceed to fetch the document. This adds security (no observer can even see where the document is located) at the cost of an extra decryption step for the receiver. In version 1, we default to plaintext URIs for simplicity, but implementers can choose to encrypt them if both sides support it. If encrypted, the URI length field would correspond to the cipher text length, and the receiver must know to decrypt those bytes (perhaps signaled by a flag).

### 3.3 Validation and Signature of Off-Chain Documents

Once a URI is obtained from the on-chain message, the receiver must retrieve the document and validate it:

**Retrieval:** The receiver uses an appropriate client to fetch the resource. For HTTPS, this means performing an HTTPS GET (or whatever method is appropriate) to the URL. The receiver should verify the TLS certificate (to avoid man-in-the-middle attacks during download). If using other schemes like SFTP, appropriate authentication (username/password or key) might be needed – those details would be pre-arranged outside this protocol. The protocol doesn’t mandate how the receiver authenticates to fetch the document, but it’s assumed that if the document is not publicly accessible, the sender will have provided access credentials or the URI itself contains an access token.

**Signature Verification:** After obtaining the document bytes, the receiver computes the HMAC-SHA256 (using the shared key) over the content. This result must exactly match the 32-byte signature included in the on-chain message. Only if it matches should the receiver accept the document as authentic and proceed to parse/use it. If it does not match, the receiver should reject the document (and possibly notify the sender or raise an error, as it implies a data integrity or security issue).

It’s important to note that **the on-chain signature ties the document to that specific payment message**. If the sender were to change the document later (even if the URL is the same), the HMAC would no longer match, and the receiver would detect it. This creates an *immutable reference*: the combination of the on-chain pointer and HMAC is effectively a commitment to a specific version of the document. If a document needs to be updated or corrected, the sender should issue a new transaction with a new URI and new HMAC (or use a versioned URL).

If the document itself contains a *digital signature* (for example, the company might sign the XML with an RSA key or include a PDF with a digital signature), that is separate from our protocol but can provide additional assurances (e.g. non-repudiation by the sender’s identity). Our protocol-level HMAC is mainly for the receiver’s assurance, given the pre-shared key context.

**Document Format:** The content at the URI is expected to be an ISO 20022-compatible message or file, typically an XML document following a schema like remt.001 (Stand-alone Remittance Advice) or camt.054 with structured remittance info, etc. The protocol does not enforce the format beyond requiring that it be parseable by the recipient’s systems. Both parties should agree on the ISO 20022 format used (including any specific message elements that identify the invoice, amounts, etc.). The advantage of using ISO 20022 XML is that it provides rich, structured fields for remittance data (e.g. multiple invoice references, amounts, dates, tax info, etc.), far beyond what a simple on-chain memo could carry. This structure can be automatically processed by ERP and treasury systems for reconciliation.

**Size Considerations:** Off-chain documents can be relatively large (potentially many kilobytes with multiple invoices). The on-chain portion only carries a fixed-size hash (HMAC) regardless of document length, so the size of the document does not affect blockchain storage – only the burden of transmitting and storing it off-chain. This is a key benefit of the pointer approach. However, extremely large documents might be slow to retrieve or verify, so in practice senders might limit the scope (for example, one remittance document per payment, covering at most a few hundred invoices or a certain time period).

**Multiple URIs:** In version 1, each message contains at most one URI. If there is a need to reference multiple documents, the recommendation is to combine them into a single archive or use one document that encapsulates others. Future versions could allow multiple URI fields if needed (e.g. flag indicating an array of URIs). But to keep things simple, we assume one remittance advice document per payment.

**Error Handling:** If the URI is unreachable (network error, resource not found, etc.), the receiver should have a fallback procedure – e.g., contacting the sender out-of-band to obtain the document. The protocol can’t guarantee delivery of off-chain content; it only provides the reference and authenticity check. It’s wise for senders to host documents reliably (with high uptime) or use decentralized hosting to avoid single points of failure.

**URI Scheme Specifics:**

* If using `ipfs://<CID>` for instance, the receiver would use an IPFS gateway or local IPFS node to fetch the content by content ID. The HMAC then confirms that the content with that CID is the expected one (though if IPFS CID is based on SHA-256 of content, it’s already an integrity check, but not an authenticity check).
* If using `swift://` (hypothetically) or other finance-specific schemes, the implementation must ensure the receiver has access to that network. For example, a `swift://` might indicate the document is available via a SWIFT FileAct or API message with a certain ID – in which case the receiver might automatically retrieve it via their SWIFT interface. The HMAC would still be used to verify the content after retrieval.

In all cases, the off-chain retrieval and verification process should be automated as much as possible, so that the end-to-end payment with remittance advice flows smoothly.

## 4. Implementation Guidelines per Network

The encoding and handling of the remittance message on-chain will differ slightly between blockchains due to their different transaction formats and capabilities. This section provides guidelines for implementing the protocol on the specified networks: Ethereum/EVM chains, Stellar, and the Ripple XRP Ledger. The aim is to maintain the same logical structure across all, while using each network’s features (logs, memos, data fields) to store the information.

### 4.1 Ethereum and EVM Chains (Logs/Events)

On Ethereum and compatible EVM chains (including Layer 2 networks), the recommended approach is to use **event logs** to carry the remittance message. Smart contract events (logs) are ideal for off-chain data signalling – they do not affect contract state and can be efficiently indexed and filtered by clients.

**Contract Design:** Implement a lightweight smart contract (or incorporate into an existing payment contract) an event for remittance messages. For example:

```solidity
event RemittanceMessage(
    uint8 version,
    bytes8 salt,
    bytes32 keyIdHash,
    bool  isURI,
    bytes data,        // encrypted payload or URI bytes
    bytes32 docHash    // HMAC for doc if isURI=true, or unused if isURI=false
);
```

In this design, the event contains fields corresponding to our protocol structure (version, salt, key hash, a flag indicating mode, the payload bytes, and the document HMAC). The `keyIdHash` is declared as `bytes32` and can be indexed (as an `indexed` event parameter). By indexing the keyIdHash, it allows an off-chain application to use Ethereum’s bloom filter and event filtering to quickly find events with a matching hash. However, recall that in v1 the keyIdHash will vary every transaction (due to salt), so filtering by a constant hash is only useful if you’re searching for a specific known hash occurrence. More commonly, a client might just filter by the event signature (topic0) and then check each event’s keyIdHash against its keys. Nonetheless, having it indexed could help in some scenarios or future modes.

**Transaction Workflow:** When sending a payment on Ethereum, the sender would typically call a function on the Remittance contract (or an integrated function in a payments contract) that does two things:

1. Transfer the asset (Ether or token) to the recipient (this could be done within the contract or separately).
2. Emit the `RemittanceMessage` event with the appropriate fields.

For example, a function could be `remitPayment(address recipient, uint256 amount, bytes remittanceMessage)` where `remittanceMessage` is the pre-formatted bytes according to our spec (magic, version, etc.), and internally the contract transfers `amount` to `recipient` (or calls an ERC-20 transfer), then emits the event by parsing those bytes into fields. Alternatively, the contract might accept the structured fields as parameters and assemble the event data itself.

If a standalone contract is used purely for logging, the sender could call `emitRemittanceMessage(bytes data)` on that contract *after* or *before* doing the actual payment (the payment might be a simple transfer). The remittance event doesn’t necessarily have to be in the same transaction as the fund transfer, but linking them is better. Ideally, they occur in one transaction for atomicity. For instance, a proxy contract or a custom token transfer function might emit the event alongside transferring funds.

**Gas and Size Considerations:** Storing data in an Ethereum event costs gas proportional to size (roughly 16 gas per zero byte, 68 gas per non-zero byte in the log data). Our message is on the order of 80–120 bytes typically, which would cost only a few thousand gas – relatively low in the context of a transaction (for example, 100 bytes of non-zero data \~ 6800 gas). This is acceptable for most use cases. It’s still wise to keep the payload lean (don’t embed large strings; use the off-chain pointer for bulk data). The magic byte and version help ensure any unintended or malformed usage can be detected early by the client, rather than processing garbage.

**Example Event Emission:**
Suppose a payment of 100 USDC (an ERC-20 token) is being made from Alice to Bob with an attached invoice detail. The app could call a combined function that (a) calls `USDC.transfer(bob, 100)` and (b) emits `RemittanceMessage(1, salt, keyHash, false, encryptedPayload, 0x0)`. The transaction log will then contain an entry with topic0 = keccak256("RemittanceMessage(uint8,bytes8,bytes32,bool,bytes,bytes32)"), topic1 = keyHash (indexed), and the data containing version, salt, isURI flag, payload bytes, and docHash (which would be zero in this case since not a pointer). Bob’s system, upon seeing this event, recognizes the signature, reads the fields, and reconstructs the message to decrypt it.

**Compatibility:** This approach works on Ethereum mainnet and any EVM chain (Polygon, BSC, Optimism, Arbitrum, etc.). On some chains, contract deployment might be an overhead; however, since this is a standard that could be reused, one might deploy a single RemittanceMessage contract and have everyone call it to emit events (though that introduces a central contract). Alternatively, each sender or each business could deploy their own instance or incorporate it into their payment contracts.

**Alternate Approaches:** One might consider using the Ethereum transaction’s `data` field to carry the message (for example, sending a transaction to a known address with the data payload only). However, using `data` without a contract means the data would just be part of an error (if sent to a non-contract) or require a specific pre-deployed “data carrier” contract at a known address. Emitting an event is cleaner and more standard. Events are specifically meant for off-chain consumers and do not require storing data in contract state, which saves cost.

**Filtering and Listening:** Recipients (and their software) will typically run a service (or use a Web3 provider) to listen for `RemittanceMessage` events. They might filter by the known contract address(es) or by topic0 (event signature). They then apply the key hash test as described. This is efficient: Ethereum clients/indexers are optimized for event filtering. Using an event aligns with this design goal of efficient detection.

**Ethereum Layer-2 Specifics:** On L2 networks (Optimistic, ZK-rollups), the same contract and event mechanism applies. One just needs to be mindful of the slightly different cost structure or any potential differences in how logs are indexed (generally the same). For rollups that post call data on L1, large logs might incur L1 data cost; again, our data size is small enough to be negligible in most cases.

### 4.2 Stellar Network (Transaction Memos and Data Entries)

Stellar provides a native memo field on transactions and also allows key-value data storage on accounts (Data Entries). We leverage both to implement this protocol, given Stellar’s strict size limits on memos.

**Memos on Stellar:** A Stellar transaction memo is an optional field that can carry up to 28 bytes of text (UTF-8) if using `MEMO_TEXT`, or 32 bytes of binary if using `MEMO_HASH`. Memos are intended to carry identifying info about transactions – for example, referencing an invoice or linking to external info. We will use the memo to carry as much of the remittance message as fits. However, 28 bytes is very limited (especially after base64 encoding an encrypted payload, it won’t fit). Therefore, two approaches are used:

* For very small payloads or pointers, we may encode directly in the memo.
* For larger data, we use account Data Entries to supplement the memo.

**Direct Memo Encoding:** If the total message (after assembling as per Section 1) can fit in 28 bytes (or 32 bytes as hash), it can be put directly as the transaction memo. For example, if the message is using pointer mode and the URL is short, one could consider putting the entire structured message in the memo. In practice, this is unlikely since even the fixed fields (magic+version+flags+salt+hash = 1+1+1+8+32 = 43 bytes) already exceed the memo limit. We might use `MEMO_HASH` (32 bytes) to store a truncated portion, but that’s not enough for full message either. Thus, **in most cases, the memo alone is insufficient** to carry the whole protocol message.

Instead, on Stellar, we recommend the following pattern:

**Combined Memo+Data Entry approach:** Utilize a Data Entry on an account to store the bulk of the message, and use the memo as a reference or pointer to that data. This approach is suggested by Stellar community practices for extending information capacity. The sender (or a service it uses) will do the following:

1. Compute the full remittance message bytes (magic, version, salt, key hash, etc., including either the encrypted payload or URI+HMAC).
2. Compute a **key** for a Data Entry, such as the SHA-256 hash of those message bytes (or another unique identifier).
3. Prior to or as part of the payment transaction, write this data to the Stellar ledger as a Data Entry under an account accessible to the sender or a related service. The Data Entry consists of a Name (the key) and a Value (the message bytes). In Stellar, a Data Entry key can be up to 64 bytes and a value up to 64 bytes. If the message bytes are larger than 64 bytes (they could be, especially if an HTTPS URL is included), one could split it across two Data Entries or consider compressing it. In many cases, the encrypted payload mode message might be \~50 bytes, which fits. A pointer mode message could be larger (URL + 32-byte HMAC + 43 bytes of header might be \~100 bytes). In such a case, splitting into two Data Entries (e.g., part1, part2) may be required.
4. In the transaction that performs the actual payment to the recipient, set the **Memo** to the key of the data entry (or a hash of the key). For example, if the Data Entry Name is the SHA-256 of the message, the Memo (of type HASH) can directly carry that 32-byte value. The memo thereby serves as a reference or pointer: the recipient sees the memo (hash) and knows to look up the data with that hash.

By doing this, the Stellar transaction carries minimal information (just the reference), and the heavy data is stored in account Data Entries which are also on-ledger but can be accessed via API. The recipient, upon seeing the transaction:

* Reads the memo (e.g. gets the hash).
* Queries the Stellar network (Horizon API) for the Data Entry on the known account (likely the sender’s account or a known data store account) with that Key. Because the DataEntry Name was chosen as the hash, the recipient can directly use the memo hash to locate the data.
* Retrieve the data bytes from the Data Entry.
* Reassemble if it was split (concatenate multiple parts in the correct order).
* Then proceed to parse the message bytes as usual (check magic, version, salt, etc.), and decrypt or fetch URI accordingly.

**Atomicity:** Stellar allows multiple operations in one transaction. An optimal method is to include the ManageData (set Data Entry) operation and the Payment operation in the *same* transaction, with the Memo referencing the data just stored. This ensures the data is written and the payment is made together. The sequence might be:

* Operation 1: ManageData (Account: sender) — Name = X (the key, e.g. hash), Value = Y (the message bytes or chunk 1 of them).
* (If needed, Operation 2: ManageData for chunk 2, etc.)
* Final Operation: Payment (or PathPayment etc.) from sender to recipient of the funds.
* Memo: X (the key or hash, indicating the data entry).

All operations execute or none (transaction atomicity), so the receiver will either see both the memo and data in place or the transaction fails. After the transaction, the data entry remains on the ledger associated with the account until it’s removed. A sender may choose to delete or update it later (e.g. after some time, they might purge old entries to save their account’s memory – though data entries cost XLM reserves, each entry requires a 0.5 XLM reserve). Alternatively, the data can be left for audit trail.

**Account for Data Entries:** The data could be stored on the sender’s account (which is simplest, but note it increases the sender’s reserve for each entry). In high volume, the sender might use a dedicated data storage account. For example, the sender could create one account that just holds remittance data entries, and all memos reference that account’s data. The recipient would need to know which account to query. This could be inferred if the memo is a hash; one approach is to include not just the hash but also an identifier of the account in the memo. But we only have 32 bytes if using Memo Hash. Perhaps instead, use `MEMO_TEXT` to put something like `<accountID>:<hash>` truncated to 28 bytes if possible (which is tough with StrKey accountIDs being \~56 chars). Realistically, the implementation would have a convention: e.g. always use the sender’s account for data. The recipient knows the sender’s account from the transaction’s source. So the recipient can check that account’s data entries for the given key. This is a logical step: “for transaction X from account A with memo hash H, look up account A’s Data Entry named H”.

**When Data Entry not needed:** If the encrypted payload is extremely small (for instance, a 16-byte invoice ID and nothing else, encrypted – which might come out to \~32 bytes encrypted), one might fit it in a Memo Hash directly. But including salt+hash overhead makes even the minimal message >32 bytes. One could choose not to include the salt and key hash if one is willing to sacrifice the filtering (not recommended). So generally, plan on using the data entry method.

**Stellar Example:**

* Alice needs to pay Bob and include remittance info. Alice and Bob share a key. Alice prepares the encrypted payload `Y` (say 48 bytes). She computes salt (8 bytes), keyHash (32 bytes) etc., forms the message bytes (maybe \~90 bytes total). She computes H = SHA256(message bytes). She creates a transaction:
  Op1: ManageData on account Alice: Name = H, Value = message bytes.
  Op2: Payment from Alice to Bob, amount X.
  Memo: type MEMO\_HASH with memoHash = H (so 32 bytes).
  She signs and submits. The transaction is successful. Bob’s system sees a payment from Alice with memo = H. It calls Horizon to get Alice’s account data entry with key H. Horizon returns the stored value (the message bytes). Bob’s system parses it, verifies keyHash matches his key, decrypts Y, etc. Now Bob optionally can delete the data entry by sending a ManageData with that Name and null value (if he has control or asks Alice to, though likely Alice should remove it if it’s not needed beyond this payment).

* If using a pointer: the message bytes might be larger (say 100 bytes) which doesn’t fit in one data entry. Alice could split it: let message = header + URI (like 70 bytes) and doc HMAC (32 bytes) => 102 bytes. She could make two data entries: Name = H1, Value = first 64 bytes; Name = H2, Value = remaining 38 bytes. The memo might only reference one (maybe H1). This gets complicated – better approach: host the *entire* ISO 20022 doc off-chain and just use the memo as pointer in simpler way. In fact, Stellar memos often directly carry *unstructured references* like invoice numbers or URLs for small things. But an HTTPS URL might not fit 28 bytes. If it’s short (e.g. a short code or a tinyurl link), it might. So another pragmatic approach on Stellar pointer mode is: skip the whole structured binary encoding for on-chain, and simply put a short code or link in MEMO\_TEXT. For example, memo = "INV12345" or memo = "[http://sho.rt/abc](http://sho.rt/abc)". Then separately secure the full details by other means. However, that wouldn’t fulfill all the security goals of this spec (no signature etc.).

Given Stellar’s constraints, using data entries as per the above method is the robust way to include our full structured message.

**Memos and Filtering:** Unlike Ethereum, Stellar does not index memos in a way you can subscribe to certain memo values easily. So the recipient likely either monitors all transactions to their address or from certain partners, or uses an external indexing service. The hashed Key ID in the message (which is inside the data entry in our approach) isn’t directly used by Stellar for filtering. Instead, the recipient in this case knows the transaction is for them because it’s to their Stellar address (the recipient address is visible in the payment). So one could simply watch for payments into the recipient account and then process memos. This is how Stellar-based services typically identify payments (e.g. an exchange uses memo to identify which user account to credit). In our case, the memo identifies the data entry to retrieve. Thus, the “filtering” by key might be less critical on Stellar; the recipient can rely on the fact that only someone with the key would create a valid decryptable payload.

**Reserve considerations:** Each Data Entry on Stellar increases the account’s minimum balance (each entry costs 0.5 XLM reserve). If a new data entry is made per payment, this can add up. The sender may want to delete old entries when no longer needed to free reserves. Deletion is done by sending ManageData with the key and a null value. This could even be done in the same transaction if clever (though doing a delete of a previous entry in the new payment tx might free 0.5 XLM after the fact, not immediately useful in that tx).

**Security:** Data entries on Stellar are publicly readable (like everything on ledger). We are storing encrypted or hashed data, so that’s fine. But note, if we stored an unencrypted URI in a data entry, it’s visible. That may leak some info. For better privacy, one might encrypt the URI (which would make it random bytes anyway). In any case, using HMAC and encryption ensures that even though we use a public data store, the content is protected.

### 4.3 Ripple XRP Ledger (Transaction Memos)

The XRP Ledger supports an arbitrary memo field on transactions as well, called **Memos**. Unlike Stellar’s single small memo, XRPL allows an array of memo objects, each containing up to 1 KB of data. This makes XRPL well-suited to carry our remittance message directly in the transaction without additional storage tricks.

**Memo Structure on XRPL:** Each transaction can include a field `"Memos"` which is an array of objects, where each object has a `"Memo"` with subfields:

* `MemoData` – hex-encoded data (arbitrary binary up to 1KB),
* `MemoType` – hex-encoded string to indicate the type of memo,
* `MemoFormat` – hex-encoded string to indicate format (like a MIME type).

We will use these fields to identify and format the remittance protocol data. Specifically:

* **MemoType:** A tag to indicate this memo is a remittance advice message. For example, we might choose `MemoType = "iso20022.remit"` (which in hex would be `0x69736F323032322E72656D6974`). This is a freeform field, but having a clear type allows clients (or block explorers) to recognize the purpose.
* **MemoFormat:** We can use a MIME type to indicate how the data is formatted. Since our message is binary, `MemoFormat = "application/octet-stream"` is appropriate for the raw bytes. If we were to encode the data differently (say as JSON or base64), we would use the corresponding format. But we will keep it binary for efficiency.
* **MemoData:** This will contain the actual message bytes (magic, version, salt, key hash, etc., up to and including payload or URI+HMAC), hex-encoded because the XRPL transaction JSON requires hex for binary data.

In practice, the XRPL serializes this into the transaction. The 1 KB size limit is more than enough for our message (even a large URL plus overhead will likely be under 300 bytes). If a document reference were extremely large (over 1KB just for URI and HMAC), XRPL allows multiple memos, so it could be split, but this should not be necessary with normal use.

**Including Payment:** On XRPL, the memos travel with a payment transaction (Payment type transaction). So a payer will create a Payment transaction to the payee’s XRPL address for X XRP or issuing token, and include the `"Memos"` field with the above contents. The payment and memo are contained in one atomic operation (either both ledger or none).

**Example XRPL JSON:**

```json
{
  "TransactionType": "Payment",
  "Account": "rw9hDF...SenderAddress...",
  "Destination": "rL5Vo...ReceiverAddress...",
  "Amount": "1000000",  /* in drops for XRP, e.g. 1 XRP = 1000000 drops */
  "Memos": [
    {
      "Memo": {
        "MemoType": "53524950",        /* "SRIP" in hex */
        "MemoFormat": "6170706C69636174696F6E2F6F63746574",/* "application/octet" in hex (truncated example) */
        "MemoData": "A501... <hex of rest of message bytes> ..."
      }
    }
  ]
}
```

*(Note: The hex strings above are illustrative; the actual hex for "application/octet-stream" would be used, and the MemoData would be the full message bytes hex encoded.)*

A consuming application will decode the hex:

* It sees `MemoType` "SRIP" (so it knows this is our protocol).
* It sees `MemoFormat` "application/octet-stream" (so it treats MemoData as binary).
* It then takes `MemoData` hex, converts to bytes, and parses according to Section 1.

If the `isURI` flag (in the message bytes) indicates a pointer, the client then takes the URI from the data and fetches the off-chain document, verifying the HMAC, etc., as described. If it's embedded, it decrypts directly.

**Filtering and Processing:** Because XRPL memos are attached to payments, the recipient can detect relevant transactions simply by looking at incoming payments to their address (just like normal). XRPL transactions do not natively filter by memo content on the ledger level; an external indexer is needed to search memos. However, given that the recipient is usually directly specified (Destination = receiver’s address), one can monitor that account’s incoming transactions. The recipient’s system can inspect each incoming transaction’s memos. If a memo with type "iso20022.remit" is present, it knows to parse it. It can then check the Key ID hash inside to ensure the key matches (an extra verification step – if it doesn’t match any known key, possibly ignore or flag).

**Security Note:** The XRPL memos are public on the ledger. We are storing either encrypted data or pointers plus HMAC. Both are safe to be public (they don't reveal invoice contents without the key; and the pointer, if not encrypted, might reveal a URL – which is a consideration). If confidentiality of the URL is important, we could encrypt the URI inside MemoData (just as with other networks). The approach is the same: the whole message bytes including the URI could be encrypted or partially encrypted. One might also choose to not include certain sensitive info in a URL (like avoid using a URL that has the company name or invoice number in plaintext if privacy is a concern).

**Multiple Memos:** XRPL allows multiple memos. It’s not necessary for our standard, but nothing prevents adding more memos alongside. For instance, a sender might include a human-readable description in another memo, or an invoice number in plain text for legacy systems. That’s outside this spec’s scope, but our protocol doesn’t forbid additional memos. The presence of the one with the known MemoType is what signals our structured data.

**XRPL Example Flow:** Alice (rAlice…) sends 50 XRP to Bob (rBob…) as payment for an invoice, and she wants to attach the remittance info. They share a key. Alice’s software creates the message bytes (say pointer mode with a URL to a remittance XML hosted at her server, plus HMAC). It then forms the Payment tx as above with memos. It submits to XRPL. Bob’s server (or client wallet) gets notified of an incoming payment. It sees the MemoType in the transaction’s meta. It decodes the MemoData, finds the salt and keyHash, matches it to Alice’s shared key, then decrypts or retrieves doc accordingly. Bob can then automatically reconcile that this XRP payment corresponds to invoice X, etc.

**Ledger Impact:** The memo data increases the size of the transaction a bit (up to \~1KB). XRPL has a network fee that grows with transaction size, but memos of a few hundred bytes are typically acceptable, just costing a slightly higher fee (fractions of XRP, usually). Validators impose limits on memo sizes (which is the 1KB limit).

One should avoid extremely large memos to not bloat the ledger. Our use case is well within acceptable bounds. As a courtesy, if the remittance document is enormous, do not try to cram it in memos – use the pointer approach.

**Alternate XRPL data fields:** The XRPL has no general data storage for transactions beyond memos. There is a DestinationTag (32-bit) and InvoiceID (256-bit) field in payments, but these are specific and not suitable for arbitrary structured data (InvoiceID is just a single 256-bit hash that could correlate a payment to an invoice, but not enough for our rich data needs). We therefore rely on memos as the proper channel.

In conclusion, **XRPL implementation** is straightforward: put the entire protocol message in a transaction memo with appropriate type/format tags. The recipient’s XRPL client should read and decode it. The XRPL’s design (high throughput, low cost per tx, and data in memos) makes it feasible to attach these messages to many transactions.

## 5. Security Considerations and Extensibility

This section discusses the security aspects of the protocol and ways it can be extended or adapted in the future.

### 5.1 Security Considerations

**Confidentiality:** The protocol ensures that detailed remittance information is not exposed publicly on-chain. In embedded mode, the sensitive data (like invoice details) are encrypted with a strong symmetric cipher. Onlookers can see the existence of a remittance message (and its length), but cannot decipher its content without the key. In pointer mode, the on-chain part does not reveal the content; it only reveals a link (which might be encrypted) and a hash. If the URI is plaintext and contains identifying info (like company names or sequential invoice IDs), there is some information leakage. To mitigate this, parties may use neutral or coded URLs (or encrypt the URI as noted). The off-chain document, if fetched via HTTPS, is encrypted in transit by TLS; however, it might reside on a server – so one should ensure the server has proper access control if the content is sensitive (or consider encrypting the document itself). One could, for example, share an AES key to encrypt the ISO 20022 XML file itself in addition to our HMAC (the recipient would then decrypt the file after downloading). This isn’t mandated in v1, but it’s an option if confidentiality of the document is required beyond transport encryption.

**Integrity:** Integrity of both on-chain and off-chain data is strongly enforced. On-chain, Ethereum logs and transactions on Stellar/XRPL are immutable once confirmed, so the data (salt, key hash, encrypted blob or URI) cannot be altered without detection. The encryption includes an authentication tag, so any tampering with the encrypted payload will be evident when decryption fails. For off-chain documents, the HMAC signature ensures that any modification to the document (even a single byte) will result in a mismatched HMAC – the receiver will know the document is not authentic. This defends against man-in-the-middle attacks or storage tampering. It is important that the receiver *always* verifies the HMAC before trusting the document content.

**Authentication (Sender Identity):** On-chain, the message is tied to the sender’s blockchain address/account. For example, on Ethereum, the event comes from a specific contract (and one could also log the sender’s address if needed); on Stellar/XRPL, the payment transaction is signed by the sender. This provides a level of authentication – the receiver can check that the funds came from the expected party’s address. However, blockchain addresses might not always perfectly map to real identities, especially in a scenario with intermediaries. Our protocol’s main authentication mechanism for the *content* is the shared key. If the sender’s address was compromised and someone else sent a payment, they would not have the correct shared secret to produce a valid encrypted message or HMAC that the receiver’s key would validate. Thus, an attacker cannot forge a believable remittance message without the secret key. They could send a random blob, but the receiver’s decryption would fail (or the key hash wouldn’t match any known key). The receiver should thus ignore messages that don’t decrypt/authenticate properly.

One potential attack vector is a **Denial-of-Service**: an attacker could spam the chain with bogus remittance events (or memos) with random data, perhaps trying to make recipients do extra work. However, because the KeyID hash won’t match, a recipient can quickly discard irrelevant messages. Even if an attacker somehow guessed a key hash that belongs to a target (which is astronomically unlikely given 256-bit space), they’d still lack the actual key to produce a valid payload or HMAC, so the receiver would discard it after attempting decryption. The computational cost for the receiver (hashing a key and trying a decryption) is low, so this is not a severe threat.

**Key Management:** The security of the whole system hinges on the shared secret keys. Key management practices are crucial:

* Parties should exchange keys securely (out-of-band, using encryption or a key agreement protocol). Never expose the key on-chain or in any public manner.
* Consider rotating keys periodically or per transaction if appropriate. For instance, a company might use a unique key per counterparty or even per invoice for maximum security. Our protocol can support that (just store new key and compute new hash accordingly).
* Store keys safely (e.g. in an HSM or secure enclave if possible, especially in corporate environments).
* If a key is suspected to be compromised, stop using it and ideally notify the counterparty to establish a new key. Any past messages with that key could potentially be decrypted by the adversary who got the key (so sensitivity of those should be evaluated).

**Privacy:** Aside from confidentiality of data, privacy regarding metadata should be considered:

* *On-chain linkability:* If the same shared key is used for many transactions and if we did not use salt, an observer could link all those transactions via the common KeyID hash. We introduced the salt specifically to prevent this linkability. With a random salt per transaction, observers cannot trivially tell that two transactions are related (unless other clues like the same sender & receiver addresses are obviously present). On public blockchains, sender and receiver addresses are usually visible, so in many cases the link is already there. But in scenarios with multiple addresses or mixers, the salted key hash adds an extra layer of ambiguity.
* *Volume and Frequency:* The presence of a magic byte might allow someone scanning memos to flag which transactions are carrying ISO 20022 remittance info. This is not necessarily a problem (it’s akin to metadata that “this is a rich payment”). In some cases, that may even be desirable (e.g., analytics could see uptake of the standard). But if it were a concern, one could always encrypt even the magic and version by merging them into the encrypted payload (though that complicates parsing). In v1 we assume it’s fine that the fact a remittance message exists is public.
* *Off-chain document privacy:* If using a public URL, anyone with that URL could theoretically fetch the document (unless access is restricted by the server). If the URL is guessable or known, an eavesdropper could attempt to retrieve it. They couldn’t verify it or decrypt it (if it’s not encrypted) without the key, but they might glean some info. To mitigate, one should use obscure URLs (with random components) or require authentication for access. Since the receiver has the key, one idea is to incorporate a secret token in the URL that only the receiver knows. For example, the URI could be `https://server.com/remit/INV12345?token=<HMAC_of_INV12345>`. Only someone with the key could generate that token to retrieve, if the server checks it. That might be overkill, but it’s an example measure.
* *Backend system privacy:* The hashed key ID in the message may sometimes be reused in internal systems (like linking to ERP records). That hash should be treated carefully – though it’s not the key, if an attacker had a guess of the key (like maybe they think the key is derived from something), seeing the hash could let them verify a guess. But since keys should be truly random, this isn’t a concern.

**Denial and Error Handling:** If a remittance message is malformed (bad version, incorrect tag, etc.), the receiver should handle gracefully – likely just ignore that message or flag it for manual review. The funds might still be transferred, so perhaps the sender will realize their mistake if the receiver asks for details. Thus, there should be a fallback communication channel in case the automated method fails (just as in traditional payments, if remittance info is lost, a human may email the details).

**Compliance:** ISO 20022 messages often contain personal or sensitive business data. When using this protocol in production, parties should ensure compliance with any data protection regulations. For example, if using public blockchains, even encrypted data might be scrutinized under certain regimes if it contained personal identifiers. Using strong encryption and keeping keys private mitigates this, but compliance officers should be consulted. Also, storing invoice data off-chain might involve data residency concerns (where is the server located, etc.). These are outside the scope of the protocol but important in a real deployment.

### 5.2 Extensibility

The protocol has been designed with extensibility in mind, to adapt to future requirements:

* **Version Byte:** The inclusion of a version number at the start allows the format to change in incompatible ways. If a new version is introduced, it could, for example, use a different hashing algorithm, a different encryption scheme, or include additional fields. Receivers should always check the version and, if they do not support it, either gracefully ignore the message or handle it in a backward-compatible mode if possible. Senders and receivers need to coordinate version upgrades (perhaps via capability flags out-of-band).

* **Flag Bits:** The flags byte (and it could be extended to more bytes if needed in a new version) provides room for feature toggles. We used one bit for payload vs pointer. Other bits could be defined:

    * e.g. a bit to indicate “URI is encrypted”,
    * a bit to indicate a different encryption algorithm (like `0= AES-GCM, 1= ChaCha20-Poly1305`),
    * or a bit to indicate the presence of an additional hash of the document for public verification.
      In future, flags might also denote multi-recipients (if one message were ever sent to multiple parties, though that’s complex with symmetric keys, likely not in scope).

* **Multiple Keys / Recipients:** This version assumes a single recipient (one key). If there was a need to send the same info to multiple recipients (each with their own key), one might extend the protocol by allowing multiple encrypted payloads or multiple HMACs for different keys in one on-chain message. That would, however, increase size and complexity. It’s more straightforward to send separate messages to each recipient. We mention this only as a theoretical possibility.

* **Public-Key Cryptography Integration:** Currently, the shared secret key paradigm is like a private bilateral channel. In future, one might integrate public-key signatures or encryption. For instance, the sender could encrypt the remittance info with the recipient’s public key (if known) rather than a pre-shared symmetric key. They could also sign the message with their own private key to prove authenticity (beyond just the blockchain signature). Some networks or applications might prefer that mode (to avoid pre-sharing secrets). The protocol could be extended by defining a new version or flag indicating that, say, `keyIdHash` actually carries an encrypted symmetric key for the recipient, or that the HMAC is replaced by a digital signature. Those changes would be significant but feasible under a new version.

* **Different Hash/Encryption Algorithms:** As cryptographic best practices evolve, we may want to upgrade the algorithms:

    * For example, if SHA-256 or AES-256-GCM are deemed weak in the far future, version 2 messages could use SHA-512, or quantum-resistant hashes, and encryption like ASCON or others. The structure can remain similar, just the algorithm behind it changes. The version byte cleanly separates these eras.
    * The protocol might also be extended to allow algorithm negotiation, but since on-chain messages are one-way, negotiation would have to be pre-arranged. It’s simpler to bump version with a new fixed choice.

* **Additional Data Fields:** We could include new metadata fields in the message. For example, a timestamp, or an explicit identifier for the transaction or recipient. Right now, we rely on the blockchain’s timestamp and addressing, and the ISO document’s internal fields for most things. But if we wanted to embed, say, an expiry for the off-chain doc (after which it should be considered stale), or a small description, it could be added after the existing fields in a future version, or as part of an extended payload.

* **Other Networks:** While we detailed Ethereum, Stellar, and XRPL, the approach can extend to other chains:

    * On **Bitcoin or UTXO chains**, one could embed the message in an OP\_RETURN output (which allows around 80 bytes on Bitcoin). That could carry perhaps the key hash and an encrypted short payload (but 80 bytes might be too tight for full structure; one might drop some fields or use multiple transactions). It’s conceivable to adapt, though Bitcoin’s ecosystem might have different standards (and ISO 20022 integration is less discussed there).
    * On **Hyperledger or other private chains**, since those might allow bigger transaction payloads or custom fields, one could incorporate this spec directly in transaction metadata.
    * On **Algorand, Cardano, etc.**: many chains have memo or note fields that could carry these bytes. As long as \~100 bytes of data can be stored with a transaction, our protocol can ride on top.

* **Integration with Payment Standards:** This protocol can complement existing standards like SWIFT gpi or others. For example, if a bank is using XRP or XLM as a bridge currency, they might map the ISO 20022 fields into our protocol for the crypto leg. This spec itself could be put forward for standardization such that wallet providers and blockchain financial systems adopt it, making it easier to interoperate with banking systems. Given that XRP and XLM are mentioned as ISO 20022 compliant cryptocurrencies, this protocol could serve as a concrete way to carry ISO 20022 content over those networks.

**Security Audits:** As an extensibility and safety note, any future changes to the protocol should be reviewed by security experts. Changing cryptographic parts or adding features can introduce new risks, so each version should undergo threat modeling and possibly formal verification for critical pieces (especially if automated in smart contracts).

**Backward Compatibility:** It’s expected that not all participants upgrade simultaneously to a new version. Thus, senders might have to send version 1 messages to some receivers and version 2 to others. Receivers might see a mix. The design (version byte) allows receivers to detect what they got. Backward compatibility strategy could be:

* Encourage a “lowest common version” approach – use the highest version that you know the recipient supports. This could be determined out-of-band or via a registry.
* Alternatively, a sender could include both versions’ info (but that’s duplication and wasteful).
* Ideally, version changes that are not fundamental could be made in a backward-compatible way (e.g. additional fields that receivers can ignore if unknown). But cryptography changes usually necessitate a bump.

In conclusion, this protocol is secure under the standard assumptions of cryptography (AES, SHA-256 are strong, keys are secret) and the trust in the underlying blockchains (transactions are final and untampered). It significantly improves the data-carrying capability of blockchain payments, allowing automation and rich context in cross-border transactions. By using a hybrid on-chain/off-chain model, it balances efficiency with completeness of data, echoing the ISO 20022 principle that a payment can carry either the full remittance info or a reference to it. The extensible design means it can adapt to future needs, fostering long-term interoperability between cryptocurrency networks and traditional financial messaging standards.

**Sources:**

* ISO 20022 remittance information and linking separate remittance messages to payments
* Stellar memos and data field capacities
* XRP Ledger memos usage and size limits
* Ethereum event logging best practices
* ISO 20022 structured vs unstructured remittance data considerations
