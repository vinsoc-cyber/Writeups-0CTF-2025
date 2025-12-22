#!/usr/bin/env python3

import json
import sys
import matplotlib.pyplot as plt

def main(json_file):
    with open(json_file, 'r') as f:
        vertices = json.load(f)['vertices']

    # Lọc vertex trắng + nằm trên mặt phẳng chữ (Y gần 0)
    text_verts = [
        v for v in vertices
        if v['color'] > 0.5 and -0.15 <= v['pos'][1] <= 0.25
    ]

    if not text_verts:
        print("[-] No text vertices found")
        return

    xs = [v['pos'][0] for v in text_verts]
    ys = [v['pos'][1] for v in text_verts]

    # Vẽ side view (X-Y)
    plt.figure(figsize=(12, 4))
    plt.scatter(xs, ys, s=15, marker='s')
    plt.xlabel('X')
    plt.ylabel('Y')
    plt.title('Side View (X-Y plane) — FLAG')
    plt.gca().set_aspect('equal', adjustable='box')
    plt.grid(True, alpha=0.3)
    plt.show()

if __name__ == '__main__':
    if len(sys.argv) != 2:
        print("Usage: python side_view.py vertices.json")
    else:
        main(sys.argv[1])
