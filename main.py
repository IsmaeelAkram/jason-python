from jason import Jason
import sys
import hashlib
import winsound

jason = Jason()
hash = sys.argv[1]
hash_type = Jason.detect_hash(hash)

def success(password, hash_type):
    print(f"Password found: {password}, {hash_type}")
    for i in [1, 1, 1]:
        winsound.Beep(1500, 350)
    sys.exit()

f = open("db.txt", "a")

memories = open("db.txt", "r").read().split('\n')
for memory in memories:
    tempMemory = memory.split(':')
    if tempMemory[2] == hash:
        success(tempMemory[0], hash_type)
        break

password = jason.dictionary_attack(hash, open(r"C:\Users\mathc\Desktop\Hacking Tools\cracking\dictionary.txt").read().split('\n'))

if password is not None:
    f.write("\n" + f"{password}:{hash_type}:{hash}")
    success(password, hash_type)
else:
    print("Cracking failed.")