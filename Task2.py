import hashlib
import random
import string

def get_sha60v(input_text):
    """Return the first 60 bits of SHA-1 hash for the provided text."""
    sha1_hash = hashlib.sha1()
    sha1_hash.update(input_text.encode('utf-8'))
    return sha1_hash.hexdigest()[:15]

def create_random_string(string_length=10):
    "Generate a random string"
    all_characters = string.ascii_letters + string.digits
    return ''.join(random.choice(all_characters) for i in range(string_length))

def find_hash_collision(num_nibbles):
    "Find a collision"
    slow_pointer = create_random_string()
    fast_pointer = create_random_string()

   
    steps_taken = 1
    while True:
        slow_hash = get_sha60v(slow_pointer)
        fast_hash = get_sha60v(get_sha60v(fast_pointer)) 

        if slow_hash[:num_nibbles] == fast_hash[:num_nibbles]:
            break

        slow_pointer = get_sha60v(slow_pointer)
        fast_pointer = get_sha60v(get_sha60v(fast_pointer))
        steps_taken += 1

    
    slow_pointer = create_random_string()  
    fast_pointer = get_sha60v(fast_pointer)  

    
    for i in range(steps_taken):
        fast_pointer = get_sha60v(fast_pointer)

    while True:
        if get_sha60v(slow_pointer)[:num_nibbles] == get_sha60v(fast_pointer)[:num_nibbles]:
            return slow_pointer, fast_pointer
        slow_pointer = get_sha60v(slow_pointer)
        fast_pointer = get_sha60v(fast_pointer)


collision_1, collision_2 = find_hash_collision(6)
print(f"Collision detected between messages: '{collision_1}' and '{collision_2}'")
print(f"SHA60v of '{collision_1}': {get_sha60v(collision_1)}")
print(f"SHA60v of '{collision_2}': {get_sha60v(collision_2)}")
