import os
import random
import string
import pyopencl as cl
import numpy as np

# OpenCL kernel code for generating passwords
cl_code = """
__kernel void generate_passwords(__global char* passwords, const int num_passwords, const int max_length, unsigned int seed) {
    int idx = get_global_id(0);
    char chars[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789!@#$%^&*()-_=+";
    unsigned int state = seed + idx;
    while (idx < num_passwords) {
        int length = (state % (max_length - 1)) + 1;
        for (int i = 0; i < length; ++i) {
            passwords[idx * max_length + i] = chars[state % (sizeof(chars) - 1)];
            state = state * 1103515245 + 12345;  // Linear congruential generator
        }
        passwords[idx * max_length + length] = '\\0';
        idx += get_global_size(0);
    }
}
"""

def generer_mot_de_passe(context, queue, program, num_passwords, max_length):
    mf = cl.mem_flags
    passwords = np.zeros((num_passwords, max_length + 1), dtype=np.uint8)
    passwords_gpu = cl.Buffer(context, mf.WRITE_ONLY, passwords.nbytes)
    seed = random.randint(0, 2**32 - 1)
    program.generate_passwords(queue, (num_passwords,), None, passwords_gpu, np.int32(num_passwords), np.int32(max_length), np.uint32(seed))
    cl.enqueue_copy(queue, passwords, passwords_gpu).wait()
    with open('C:/fsociety/words.txt', "a") as f:
        for i in range(num_passwords):
            password = ''.join([chr(c) for c in passwords[i] if c != 0])
            
            print(f"Numéro : {i} | Mot de passe généré : {password}", end="\r")
            f.write(f'{password}\n')

def main():
    with open('numbers.txt', 'r') as f:
        num_passwords = int(f.read())
    max_length = 20  # Maximum length of each password

    # Setup OpenCL
    platform = cl.get_platforms()[0]
    device = platform.get_devices(device_type=cl.device_type.GPU)[0]
    context = cl.Context([device])
    queue = cl.CommandQueue(context)
    program = cl.Program(context, cl_code).build()
    try:
        os.system('cls')
    except:
        os.system('clear')
    generer_mot_de_passe(context, queue, program, num_passwords, max_length)

if __name__ == "__main__":
    main()
