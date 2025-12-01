# integrity.py

import hashlib

def sha256(data):
    return hashlib.sha256(data).digest()

def build_merkle_tree(leaves):
    """
    Takes a list of leaf hashes (bytes).
    Returns (root_hash, tree_levels).
    """
    if not leaves:
        return b'\x00'*32, []
        
    levels = [leaves]
    current_level = leaves
    
    while len(current_level) > 1:
        next_level = []
        for i in range(0, len(current_level), 2):
            left = current_level[i]
            if i + 1 < len(current_level):
                right = current_level[i+1]
            else:
                right = left # Duplicate last node if odd
            
            parent = sha256(left + right)
            next_level.append(parent)
        current_level = next_level
        levels.append(current_level)
        
    return current_level[0], levels

def get_merkle_proof(index, levels):
    """Generates the proof path for a specific leaf index."""
    proof = []
    for level in levels[:-1]: # Don't need root in proof
        is_right_child = (index % 2 == 1)
        sibling_index = index - 1 if is_right_child else index + 1
        
        if sibling_index < len(level):
            proof.append((level[sibling_index], "L" if is_right_child else "R"))
        else:
            # Sibling is self (duplicate case)
            proof.append((level[index], "L" if is_right_child else "R"))
            
        index //= 2
    return proof