from mpi4py import MPI
import oqs
import numpy as np
import os
import time
import queue
import threading
import subprocess
import mmap

from Crypto.Cipher import AES
from concurrent.futures import ThreadPoolExecutor, ProcessPoolExecutor
from secretsharing import PlaintextToHexSecretSharer as Shamir
from qiskit_aer import Aer
from qiskit import QuantumCircuit, transpile


comm = MPI.COMM_WORLD
rank = comm.Get_rank()
size = comm.Get_size()

def bb84_worker(seed):
    np.random.seed(seed)
    a_bit = np.random.randint(2)
    a_base = np.random.randint(2)
    b_base = np.random.randint(2)
    qc = QuantumCircuit(1, 1)
    qc.reset(0)
    if a_bit == 1:
        qc.x(0)
    if a_base == 1:
        qc.h(0)
    if b_base == 1:
        qc.h(0)
    qc.measure(0, 0)
    backend = Aer.get_backend('qasm_simulator')
    job = backend.run(transpile(qc, backend), shots=128)
    result = job.result()
    counts = result.get_counts()
    measurement = int(max(counts, key=counts.get))
    return a_bit, a_base, b_base, measurement

def run_bb84_parallel(required_key_bits=128, workers=8):
    alice_key = []
    bob_key = []
    loop_count = 0
    while len(alice_key) < required_key_bits:
        loop_count += 1
        seeds = np.random.randint(0, 100000, size=required_key_bits)
        with ProcessPoolExecutor(max_workers=workers) as executor:
            for a_bit, a_base, b_base, measurement in executor.map(bb84_worker, seeds):
                if a_base == b_base:
                    alice_key.append(a_bit)
                    bob_key.append(measurement)
                if len(alice_key) >= required_key_bits:
                    break
        errors = sum(a != b for a, b in zip(alice_key, bob_key))
        qber = errors / required_key_bits
        if qber > 0.11:
            alice_key.clear()
            bob_key.clear()
    return alice_key[:required_key_bits], loop_count


def aes_encrypt_chunk(data, key):
    cipher = AES.new(key, AES.MODE_CTR)
    return cipher.nonce + cipher.encrypt(data)

def aes_decrypt_chunk(idx_chunk_pair, key):
    idx, encrypted_chunk = idx_chunk_pair
    nonce = encrypted_chunk[:8]
    ciphertext_part = encrypted_chunk[8:]
    decrypted_chunk = AES.new(key, AES.MODE_CTR, nonce=nonce).decrypt(ciphertext_part)
    return idx, decrypted_chunk

def xor_encrypt(data_bytes, qkd_slice_bytes):
    ext_key = (qkd_slice_bytes * ((len(data_bytes) // len(qkd_slice_bytes)) + 1))[:len(data_bytes)]
    return bytes(a ^ b for a, b in zip(data_bytes, ext_key))

def xor_decrypt(data_bytes, qkd_slice_bytes):
    return xor_encrypt(data_bytes, qkd_slice_bytes)

# ==========================================================
# Main
# ==========================================================

if __name__ == "__main__":


    mpstat_log_file = f"mpstat_rank{rank}.log"
    mpstat_proc = subprocess.Popen(
        ["mpstat", "-P", "ALL", "1"],
        stdout=open(mpstat_log_file, "w"),
        stderr=subprocess.DEVNULL
    )
    
    overall_start = time.time()
    num_slaves = size - 1
    chunk_size = 8 * 1024 * 1024
    batch_size = 100
    filepath = "ECU-IoHT-Dataset_50GB.csv"

    if rank == 0:
        print("[KCJ:Master] * Phase: File Open")
        file_load_start = time.time()
        file_size = os.path.getsize(filepath)
        file_load_end = time.time()
        print(f"[KCJ:Timing] File size check took {file_load_end - file_load_start:.3f} sec")

        total_chunks = (file_size + chunk_size - 1) // chunk_size
        print(f"[KCJ:Master] * Auto-tuned parameters: chunk_size = {chunk_size // (1024*1024)}MB, chunk_num = {total_chunks}")

        print("[KCJ:Master] * Phase: PQC KeyGen + Encapsulation")
        pqc_start = time.time()
        kem = oqs.KeyEncapsulation("Kyber512")
        public_key = kem.generate_keypair()
        private_key = kem.export_secret_key()
        ciphertext, shared_secret = kem.encap_secret(public_key)
        aes_key = shared_secret[:16]
        pqc_end = time.time()
        print(f"[KCJ:Timing] PQC keygen + encapsulation took {pqc_end - pqc_start:.3f} sec")

        print("[KCJ:Master] * Phase: BB84 QKD Protocol")
        bb84_start = time.time()
        qkd_bits, loop_count = run_bb84_parallel(128, workers=8)
        bb84_end = time.time()
        print(f"[KCJ:Timing] BB84 QKD protocol took {bb84_end - bb84_start:.3f} sec")
        print(f"[KCJ:Master] * QKD loop count until success: {loop_count}")


        qkd_key_bytes = bytes([int("".join(map(str, qkd_bits[i:i+8])), 2) for i in range(0, 128, 8)])
        xor_private_key = xor_encrypt(private_key, qkd_key_bytes)

        for slave_id in range(1, size):
            comm.send((aes_key, xor_private_key, ciphertext, file_size), dest=slave_id, tag=100+slave_id)

    else:
        aes_key, xor_private_key, ciphertext, file_size = comm.recv(source=0, tag=100+rank)

    comm.Barrier()

    if rank != 0:
        print(f"[KCJ:Slave {rank}] * Phase: File Read + AES Encryption Start")
        my_start = (rank-1) * (file_size // num_slaves)
        my_end = file_size if (rank == size-1) else rank * (file_size // num_slaves)

        task_queue = queue.Queue(maxsize=256)
        stop_token = object()

        def worker_thread():
            true_enc_start = time.time()
            with open(filepath, 'rb') as f:
                f.seek(my_start)
                current = my_start
                idx = my_start // chunk_size
                while current < my_end:
                    read_size = min(chunk_size, my_end - current)
                    data = f.read(read_size)
                    enc_chunk = aes_encrypt_chunk(data, aes_key)
                    task_queue.put((idx, enc_chunk))
                    current += read_size
                    idx += 1
            true_enc_end = time.time()
            print(f"[KCJ:Slave {rank}] * True AES encryption time: {true_enc_end - true_enc_start:.3f} sec")
            task_queue.put(stop_token)

        threading.Thread(target=worker_thread, daemon=True).start()

        send_start = time.time()
        pending_requests = []
        batch = []
        batch_idx = 0

        send_only_total_time = 0.0  # <-- 총 전송 시간 누적 변수

        while True:
            item = task_queue.get()
            if item is stop_token:
                break
            batch.append(item)

            if len(batch) == batch_size:
                send_batch_start = time.time()
                req = comm.isend(batch, dest=0, tag=(200 + rank * 10000 + batch_idx) % 30000)
                send_batch_end = time.time()
                send_only_total_time += (send_batch_end - send_batch_start)

                pending_requests.append(req)
                batch = []
                batch_idx += 1

                if len(pending_requests) >= 32:
                    MPI.Request.Waitall(pending_requests)
                    pending_requests.clear()

        if batch:
            send_batch_start = time.time()
            req = comm.isend(batch, dest=0, tag=(200 + rank * 10000 + batch_idx) % 30000)
            send_batch_end = time.time()
            send_only_total_time += (send_batch_end - send_batch_start)
            pending_requests.append(req)

        if pending_requests:
            MPI.Request.Waitall(pending_requests)

        send_end = time.time()

        print(f"[KCJ:Slave {rank}] * True Send-only time: {send_only_total_time:.3f} sec")
        print(f"[KCJ:Slave {rank}] * Total (Encrypt + Send) wall-time: {send_end - overall_start:.3f} sec")


    if rank == 0:
        print("[KCJ:Master] * Phase: Data Gather from Slaves")
        gather_start = time.time()
        received_chunks = {}

        for slave_id in range(1, size):
            my_start = (slave_id-1) * (file_size // num_slaves)
            my_end = file_size if (slave_id == size-1) else slave_id * (file_size // num_slaves)
            my_chunk_start = my_start // chunk_size
            my_chunk_end = (my_end + chunk_size - 1) // chunk_size
            total_batches = (my_chunk_end - my_chunk_start + batch_size - 1) // batch_size

            for batch_idx in range(total_batches):
                batch = comm.recv(source=slave_id, tag=(200 + slave_id * 10000 + batch_idx) % 30000)
                for chunk_idx, encrypted_chunk in batch:
                    received_chunks[chunk_idx] = encrypted_chunk

        gather_end = time.time()
        print(f"[KCJ:Timing] Slave → Master recv total time: {gather_end - gather_start:.3f} sec")

        print("[KCJ:Master] * Phase: PQC Key Recovery")
        recover_start = time.time()
        kem = oqs.KeyEncapsulation("Kyber512")
        kem.secret_key = xor_decrypt(xor_private_key, qkd_key_bytes)
        recovered_secret = kem.decap_secret(ciphertext)
        recovered_aes_key = recovered_secret[:16]
        recover_end = time.time()
        print(f"[KCJ:Timing] PQC private key recovery took {recover_end - recover_start:.3f} sec")

        print("[KCJ:Master] * Phase: AES Decryption Start")
        decrypt_start = time.time()
        
        # Step 1: chunk index 기준 정렬 (순서 보장용)
        chunk_items = sorted(received_chunks.items())
        
        # Step 2: output 파일 스트리밍 write
        with open("recovered_output.csv", "wb") as f:
            def decrypt_and_write(pair):
                idx, encrypted_chunk = pair
                nonce = encrypted_chunk[:8]
                ciphertext = encrypted_chunk[8:]
                decrypted = AES.new(recovered_aes_key, AES.MODE_CTR, nonce=nonce).decrypt(ciphertext)
                return idx, decrypted
        
            with ThreadPoolExecutor(max_workers=32) as executor:
                for idx, decrypted_chunk in executor.map(decrypt_and_write, chunk_items):
                    # write는 반드시 순서대로
                    f.write(decrypted_chunk)
        
        decrypt_end = time.time()
        print(f"[KCJ:Master] * AES decryption (streamed write) time: {decrypt_end - decrypt_start:.3f} sec")




'''
        decrypt_start = time.time()
        chunk_items = sorted(received_chunks.items())

        with ThreadPoolExecutor(max_workers=16) as executor:
            decrypted_chunks = list(executor.map(lambda pair: aes_decrypt_chunk(pair, recovered_aes_key), chunk_items))

        decrypted_data = bytearray()
        for idx, chunk in sorted(decrypted_chunks):
            decrypted_data.extend(chunk)
        
        decrypt_end = time.time()
        print(f"[KCJ:Master] * AES decryption time: {decrypt_end - decrypt_start:.3f} sec")
        
        with open("recovered_output.csv", "wb") as f:
            f.write(decrypted_data)
'''
        #total_end = time.time()
        #print(f"[Time] * Total end-to-end time: {total_end - overall_start:.3f} sec")
    
    #mpstat_proc.terminate()

