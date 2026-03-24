import sys
import json
import os
import hashlib

def calculate_file_SHA256(file):
    with open(file, "rb") as f:
        return hashlib.sha256(f.read()).digest()


def create_tree(files):
    merkle_tree = [] 
    leafs= []
    if  len(files) % 2 == 1: files.append(files[-1])

    for file in files:
        fileSHA256 = calculate_file_SHA256(file)
        leafs.append(fileSHA256)
    
    merkle_tree.append(leafs)

    while len(merkle_tree[0]) != 1:
        iteration = len(merkle_tree[0])
        branch = []
        for i in range(0, iteration, 2):
            concat = merkle_tree[0][i] + merkle_tree[0][i+1]
            hash_bytes = hashlib.sha256(concat).digest()
            branch.append(hash_bytes)

        merkle_tree.insert(0,branch)
    return merkle_tree

def find_brothers(leaf, merkle_tree):
    leaf_layer = merkle_tree[-1]
    proof = []
    index = leaf_layer.index(leaf)

    for level in reversed(merkle_tree):

        if index % 2 == 0:
            brother_index = index + 1
            position = "right"
        else:
            brother_index = index - 1
            position = "left"
        if 0 <= brother_index < len(level):
            brother_hash = level[brother_index]
            proof.append({"position": position, "hash": brother_hash})
        index = index // 2
    return proof

def create_json(file_name, leaf, merkle_tree):

    json_path = os.path.join('./jsons', file_name+'.merkle.json')
    os.makedirs(os.path.dirname(json_path), exist_ok=True)
    brothers = find_brothers(leaf, merkle_tree)

    proof = [
        {"position": b["position"], "hash": b["hash"].hex()}
        for b in brothers
    ]
    json_data = {
        "root": merkle_tree[0][0].hex(),
        "proof": proof
    }
    with open(json_path, 'w') as file:
        json.dump(json_data, file, indent=2)

def verify_proof(file_path, merkle_json_path):
    with open(file_path, "rb") as f:
        file_hash = hashlib.sha256(f.read()).digest()

    with open(merkle_json_path, "r") as f:
        merkle_data = json.load(f)

    proof = [
        {"position": p["position"], "hash": bytes.fromhex(p["hash"])}
        for p in merkle_data["proof"]
    ]
    root = bytes.fromhex(merkle_data["root"])

    current_hash = file_hash
    for p in proof:
        if p["position"] == "left":
            current_hash = hashlib.sha256(p["hash"] + current_hash).digest()
        else:  
            current_hash = hashlib.sha256(current_hash + p["hash"]).digest()

    print(str(current_hash == root).lower())

if __name__ == "__main__":
    command = sys.argv[1]
    files = sys.argv[2:]

    if command == "treegen":
        merkle_tree = create_tree(files)
        for file in files: 
            create_json(os.path.splitext(os.path.basename(file))[0], merkle_tree[-1][files.index(file)], merkle_tree)

    elif command == "verify":
        verify_proof(files[0], files[1])
    else: 
        print("Please chose a command between [treegen, verify]")
        sys.exit(-1)



