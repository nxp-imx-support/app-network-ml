/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2025 NXP
 */

#include <stdio.h>
#include <string.h>
#include <sys/ipc.h>
#include <sys/shm.h>


const int shm_key = 0x2333;
const int block_size = 4 * 1024;

int create_shm_block(size_t mem_size) {
    int shm_id = shmget(shm_key, mem_size, 0640 | IPC_CREAT);
    if (shm_id < 0) {
        return -1;
    }
    return shm_id;
}

void destory_shm_block(int shm_id) {
    int ret = shmctl(shm_id, IPC_RMID, NULL);
    if (ret == -1) {
        printf("Destory share mem failed.\n");
        return;
    }
    return;
}

int write_int(int shm_id, int param) {
    int* ptr = NULL;
    printf("In write, shm_id=%d\n", shm_id);
    ptr = (int*)shmat(shm_id, NULL, 0);
    if (ptr == (void*)-1)
        return -1;
    printf("ready to write.\n");
    *ptr = param;
    shmdt(ptr);
    return 0;
}

/*
* Write buf_len bytes from buf to shared memory.
*/
int write_to_shm(int shm_id, size_t offset, size_t buf_len, const char* buf) {
    printf("In write_to_shm, shm_id=%d\n", shm_id);
    char* ptr = NULL;
    ptr = (char*)shmat(shm_id, NULL, 0);
    if (ptr == (void*)-1)   return -1;
    printf("ready to write.\n");
    memcpy(ptr + offset, buf, buf_len);
    shmdt(ptr);
    return 0;
}

int read_int(int shm_id) {
    int* ptr = NULL;
    ptr = (int*)shmat(shm_id, NULL, 0);
    int ret = *ptr;
    shmdt(ptr);
    return ret;
}

/**
 * Read buf_len bytes from shared memory to read_buf
 */
int read_frm_shm(int shm_id, size_t offset, size_t buf_len, char* read_buf) {
    char* ptr = NULL;
    ptr = (char*)shmat(shm_id, NULL, 0);
    if (ptr == (void*)-1) return -1;
    printf("ready to read.\n");
    memcpy(read_buf, ptr + offset, buf_len);
    shmdt(ptr);
    return 0;
}


