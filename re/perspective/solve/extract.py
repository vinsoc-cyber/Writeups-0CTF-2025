#!/usr/bin/env python3

import idc
import idaapi
import struct
import json

def export_vertices_to_json(output_file="vertices.json"):
    """Export all 628 vertices to JSON file"""
    
    pos_addr = 0x14005E7C0
    color_addr = 0x1400622A0
    norm_addr = 0x140060530
    
    print("[*] Extracting 628 vertices...")
    
    vertices = []
    for i in range(628):
        # Position
        x = struct.unpack('f', idc.get_bytes(pos_addr + i*12, 4))[0]
        y = struct.unpack('f', idc.get_bytes(pos_addr + i*12 + 4, 4))[0]
        z = struct.unpack('f', idc.get_bytes(pos_addr + i*12 + 8, 4))[0]
        
        # Normal
        nx = struct.unpack('f', idc.get_bytes(norm_addr + i*12, 4))[0]
        ny = struct.unpack('f', idc.get_bytes(norm_addr + i*12 + 4, 4))[0]
        nz = struct.unpack('f', idc.get_bytes(norm_addr + i*12 + 8, 4))[0]
        
        # Color
        c = struct.unpack('f', idc.get_bytes(color_addr + i*4, 4))[0]
        
        vertices.append({
            'index': i,
            'pos': [round(x, 4), round(y, 4), round(z, 4)],
            'normal': [round(nx, 4), round(ny, 4), round(nz, 4)],
            'color': round(c, 4)
        })
    
    # Write to JSON file
    with open(output_file, 'w') as f:
        json.dump({
            'total_vertices': len(vertices),
            'vertices': vertices
        }, f, indent=2)
    
    print(f"[+] Exported {len(vertices)} vertices to {output_file}")
    
    # Statistics
    white = sum(1 for v in vertices if v['color'] > 0.5)
    black = sum(1 for v in vertices if v['color'] < 0.5)
    
    print(f"\n[*] Statistics:")
    print(f"    White vertices: {white}")
    print(f"    Black vertices: {black}")
    print(f"    Total: {len(vertices)}")
    
    # Find bounds
    xs = [v['pos'][0] for v in vertices]
    ys = [v['pos'][1] for v in vertices]
    zs = [v['pos'][2] for v in vertices]
    
    print(f"\n[*] Bounds:")
    print(f"    X: [{min(xs):.2f}, {max(xs):.2f}]")
    print(f"    Y: [{min(ys):.2f}, {max(ys):.2f}]")
    print(f"    Z: [{min(zs):.2f}, {max(zs):.2f}]")

export_vertices_to_json("vertices.json")

