import socket
import hashlib
import random
import numpy as np
import string
import time
from itertools import product

def solve_pow(challenge, difficulty):
    prefix = challenge
    suffix_length = 6  # Start with a reasonable length
    charset = string.ascii_letters + string.digits
    
    while True:
        # Generate random suffixes of the current length
        for _ in range(1000):  # Try 1000 random suffixes at a time
            suffix = ''.join(random.choice(charset) for _ in range(suffix_length))
            test_string = prefix + suffix
            hash_result = hashlib.sha256(test_string.encode()).hexdigest()
            
            if hash_result.startswith('0' * difficulty):
                return suffix
        
        # If no solution found, increase suffix length
        suffix_length += 1

def connect_to_server(host, port):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect((host, port))
    return s

def receive_until(s, delimiter):
    data = b''
    while delimiter not in data:
        data += s.recv(4096)
    return data.decode()

def analyze_vector(vector):
    # For bit=0 vectors, most elements are generated deterministically based on previous elements
    # For bit=1 vectors, all elements are random
    
    # Let's check if the vector follows a pattern by looking at the correlation between elements
    # In bit=0 vectors, there should be more correlation between elements
    
    # Calculate the correlation between consecutive elements
    correlation = 0
    for i in range(1, len(vector)):
        if abs(vector[i] - vector[i-1]) < 100:  # Threshold for "similar" values
            correlation += 1
    
    # If there's high correlation, it's likely a bit=0 vector
    if correlation > 50:  # Threshold can be adjusted
        return 0
    else:
        return 1

def main():
    host = 'instance.penguin.0ops.sjtu.cn'
    port = 18345
    
    # Connect to the server
    s = connect_to_server(host, port)
    
    # Get the proof of work challenge
    data = receive_until(s, b'Enter your answer: ')
    print(data)
    
    # Extract challenge and difficulty
    lines = data.split('\n')
    challenge_line = [line for line in lines if 'sha256(' in line][0]
    challenge = challenge_line.split('sha256(')[1].split(' + ')[0].strip()
    difficulty = challenge_line.count('0')
    
    # Solve the proof of work
    solution = solve_pow(challenge, difficulty)
    print(f"Solution: {solution}")
    
    # Send the solution
    s.sendall(solution.encode() + b'\n')
    
    # Get the banner and play the game
    data = receive_until(s, b'Are u ready to play the game\n')
    print(data)
    
    # Play 200 rounds
    for i in range(200):
        # Get the vector
        data = receive_until(s, b'Please tell me the bit of the vector\n')
        print(data)
        
        # Extract the vector
        vector_line = [line for line in data.split('\n') if 'Vector:' in line][0]
        vector_str = vector_line.split('Vector: ')[1].strip()
        vector = eval(vector_str)  # Using eval to parse the list
        
        # Analyze the vector
        bit = analyze_vector(vector)
        print(f"Round {i+1}: Determined bit = {bit}")
        
        # Send our answer
        s.sendall(f"{bit}\n".encode())
        
        # Get the response
        response = s.recv(1024).decode()
        print(response)
        
        if "Wrong answer" in response:
            print("Failed at round", i+1)
            break
        elif "flag" in response:
            print("Got the flag!")
            print(response)
            break
    
    s.close()

if __name__ == "__main__":
    main()