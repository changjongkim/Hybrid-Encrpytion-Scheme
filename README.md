# HybridEncryptionScheme
Secure and Scalable File Encryption via Distributed Integration of Quantum and Classical Cryptography


## Introduction
HybridEncrypt is a distributed hybrid encryption framework that integrates Post-Quantum Cryptography (PQC), Quantum Key Distribution (QKD), and AES-based file encryption for secure and scalable processing in cloud systems.  
To achieve both quantum-resilient security and parallel performance, HybridEncrypt introduces:
- Centralized key management using Kyber (PQC) and BB84 (QKD),
- Offset-aware file partitioning and chunk-based AES encryption,
- Pipelined encryption and transmission architecture for high-throughput processing.

The framework enables secure key encapsulation and masking at the master node, while allowing each slave node to independently encrypt file chunks in parallel.  
Our evaluation demonstrates up to **8.11×** speedup in encryption performance and **2.37×** improvement in end-to-end runtime compared to conventional AES-based encryption.

## Key Features
- Hybrid key protection using Kyber-based PQC encapsulation and BB84-based QKD masking.
- Scalable parallel encryption by distributing AES-CTR tasks across slave nodes.
- Offset-aware chunking to enable parallel disk I/O and minimize memory contention.
- Overlapped encryption-transmission pipeline for reduced latency and improved resource utilization.
- Centralized decryption with in-order reassembly and thread-parallel subset decryption.

## Modified Components
HybridEncrypt is implemented in approximately 280 lines of Python code using the following libraries:
- `mpi4py` for distributed message passing,
- `oqs-python` for PQC key encapsulation (Kyber512),
- `qiskit-aer` for simulating BB84 QKD,
- `pycryptodome` for AES-CTR encryption/decryption.

The following modules constitute the core components:
- `HybridCryptoUnit`: Handles AES key generation, Kyber encapsulation, and QKD-based key masking.
- `Cipher Dispatcher` / `Cipher Sender`: Partition file offsets and manage MPI-based subset transmission.
- `AES Encryptor` / `Cipher Reader`: Read and encrypt file subsets using the reconstructed AES key.
- `Cipher Sorter` / `Decryptor`: Reassemble and decrypt subsets centrally at the master node.
