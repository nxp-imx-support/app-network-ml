#include <stdio.h>

#ifdef __cplusplus
extern "C" {
#endif
    int create_shm_block(size_t mem_size);
    void destory_shm_block(int shm_id);
    int write_int(int shm_id, int param);
    int read_int(int shm_id);
    int write_to_shm(int shm_id, size_t offset, size_t buf_len, const char* buf);
    int read_frm_shm(int shm_id, size_t offset, size_t buf_len, char* read_buf);
    
    void sem_post_wrapper();
    void sem_wait_wrapper();
#ifdef __cplusplus
}
#endif
