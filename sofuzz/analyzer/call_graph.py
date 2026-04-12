"""
SOFuzz - Call Graph Analyzer
Builds and analyzes the call graph of an ELF file using capstone and networkx.
"""

import networkx as nx
from typing import Dict, List, Optional, Set

try:
    import capstone
    from capstone import x86, arm, arm64
except ImportError:
    capstone = None

from ..utils.logger import get_logger
from .elf_parser import ELFParser
from .symbol_extractor import SymbolExtractor, Symbol

class CallGraph:
    """
    Builds a Directed Graph (Call Graph) from analyzed ELF binaries
    using Capstone engine for disassembly.
    """
    def __init__(self, file_path: str):
        self.file_path = file_path
        self.logger = get_logger()
        self.parser = ELFParser(file_path)
        self.symbol_extractor = SymbolExtractor(file_path)
        self.graph = nx.DiGraph()
        
        self.functions: Dict[int, Symbol] = {}  # address -> Symbol
        
    def build(self) -> nx.DiGraph:
        """Parse ELF symbol tables and instructions to build the directed call graph"""
        sym_table = self.symbol_extractor.extract()
        for func in sym_table.functions:
            self.functions[func.value] = func
            self.graph.add_node(func.value, name=func.name, size=func.size)
            
        elf_info = self.parser.parse()
        if not elf_info.is_valid:
            self.logger.error("Cannot build call graph: Invalid ELF")
            return self.graph
            
        if not capstone:
            self.logger.error("Capstone not available. Call graph will be empty.")
            return self.graph

        is_64 = elf_info.header.is_64bit
        machine = elf_info.header.machine_name.lower()
        
        # Match the architecture for capstone
        arch = capstone.CS_ARCH_ARM64 if is_64 else capstone.CS_ARCH_ARM
        mode = capstone.CS_MODE_ARM
        
        if 'x86_64' in machine or 'amd64' in machine:
            arch = capstone.CS_ARCH_X86
            mode = capstone.CS_MODE_64
        elif '386' in machine or '86' in machine:
            arch = capstone.CS_ARCH_X86
            mode = capstone.CS_MODE_32
        elif 'aarch64' in machine:
            arch = capstone.CS_ARCH_ARM64
            mode = capstone.CS_MODE_ARM
        elif 'arm' in machine:
            arch = capstone.CS_ARCH_ARM
            mode = capstone.CS_MODE_ARM
        
        try:
            md = capstone.Cs(arch, mode)
            md.detail = True
        except Exception as e:
            self.logger.error(f"Failed to initialize capstone engine: {e}")
            return self.graph
            
        # We need to disassemble .text section to identify instruction calls
        text_section = None
        for sec in elf_info.sections:
            if sec.name == ".text":
                text_section = sec
                break
                
        if not text_section:
            self.logger.warning("No .text section found, skipping disassembly.")
            return self.graph
            
        text_data = self.parser.get_section_data(text_section)
        text_addr = text_section.sh_addr
        
        # Associate instructions with function symbols
        sorted_funcs = sorted([f for f in self.functions.values() if f.value >= text_addr and f.value < text_addr + text_section.sh_size], key=lambda x: x.value)
        
        current_func_addr = None
        func_idx = 0
        
        for i in md.disasm(text_data, text_addr):
            # Advance current function if we passed its boundary
            while func_idx < len(sorted_funcs):
                f = sorted_funcs[func_idx]
                if i.address >= f.value and i.address < f.value + max(f.size, 4):
                    current_func_addr = f.value
                    break
                elif i.address >= f.value + max(f.size, 4):
                    func_idx += 1
                else:
                    current_func_addr = None
                    break
                    
            if not current_func_addr:
                continue
                
            is_call = False
            target_addr = None
            
            mnemonic = i.mnemonic.strip()
            
            # Architecture specific branch detection
            if arch == capstone.CS_ARCH_X86 and mnemonic.startswith('call'):
                is_call = True
                if len(i.operands) > 0 and i.operands[0].type == x86.X86_OP_IMM:
                    target_addr = i.operands[0].value.imm
            elif arch in (capstone.CS_ARCH_ARM, capstone.CS_ARCH_ARM64) and mnemonic.startswith('bl'):
                is_call = True
                if arch == capstone.CS_ARCH_ARM and len(i.operands) > 0 and i.operands[0].type == arm.ARM_OP_IMM:
                    target_addr = i.operands[0].value.imm
                elif arch == capstone.CS_ARCH_ARM64 and len(i.operands) > 0 and i.operands[0].type == arm64.ARM64_OP_IMM:
                    target_addr = i.operands[0].value.imm
                        
            if target_addr and target_addr in self.functions:
                self.graph.add_edge(current_func_addr, target_addr)
                
        return self.graph
        
    def get_reachable_nodes(self, start_address: int) -> Set[int]:
        """Get all function addresses reachable from a start address"""
        if start_address not in self.graph:
            return set()
        return set(nx.descendants(self.graph, start_address))
        
    def reaches_risky_functions(self, start_address: int, risky_names: List[str]) -> bool:
        """Check if a start function reaches any known risky functions based on naming"""
        reachable = self.get_reachable_nodes(start_address)
        for addr in reachable:
            node_data = self.graph.nodes[addr]
            name = node_data.get('name', '').lower()
            for risky in risky_names:
                if risky in name:
                    return True
        return False

    def find_callbacks(self) -> List[Dict[str, str]]:
        """Phase 3: Bidirectional Callback Analysis. Finds native functions that call back into Java via JNI Call*Method"""
        callbacks = []
        callback_keywords = [
            "CallObjectMethod", "CallVoidMethod", "CallBooleanMethod", 
            "CallByteMethod", "CallCharMethod", "CallShortMethod",
            "CallIntMethod", "CallLongMethod", "CallFloatMethod", "CallDoubleMethod",
            "CallStaticObjectMethod", "CallStaticVoidMethod"
        ]
        
        for u, v in self.graph.edges():
            caller = self.graph.nodes[u].get('name', 'unknown')
            callee = self.graph.nodes[v].get('name', 'unknown')
            
            for keyword in callback_keywords:
                if keyword in callee:
                    callbacks.append({
                        "native_caller": caller,
                        "jni_method": callee,
                        "type": "Bidirectional Java Callback"
                    })
                    self.logger.warning(f"Bidirectional Callback Detected: {caller} -> {callee}")
                    break
        
        return callbacks

    def export_dot(self, output_path: str, risky_names: List[str]) -> None:
        """Export call graph to a DOT file with highlighted JNI paths and risky functions."""
        try:
            with open(output_path, 'w') as f:
                f.write("digraph CallGraph {\n")
                f.write('  node [shape=box, style=filled, fillcolor=white, fontname="Helvetica", fontsize=10];\n')
                f.write('  edge [fontname="Helvetica", fontsize=10];\n')
                
                jni_nodes = set()
                risky_nodes = set()
                
                for node, data in self.graph.nodes(data=True):
                    name = data.get('name', '')
                    if name.startswith('Java_'):
                        jni_nodes.add(node)
                    
                    name_lower = name.lower()
                    for risky in risky_names:
                        if risky in name_lower:
                            risky_nodes.add(node)
                            break
                            
                highlight_edges = set()
                for jni in jni_nodes:
                    for risky in risky_nodes:
                        if nx.has_path(self.graph, jni, risky):
                            try:
                                paths = nx.all_shortest_paths(self.graph, jni, risky)
                                for path in paths:
                                    for i in range(len(path)-1):
                                        highlight_edges.add((path[i], path[i+1]))
                            except nx.NetworkXNoPath:
                                pass
                                
                for node, data in self.graph.nodes(data=True):
                    name = data.get('name', 'unknown')
                    name_esc = name.replace('"', '\\"')
                    
                    color = "white"
                    if node in jni_nodes:
                        color = '"lightblue"'
                    elif node in risky_nodes:
                        color = '"salmon"'
                        
                    label = f'"{name_esc}"'
                    f.write(f'  "{node}" [label={label}, fillcolor={color}];\n')
                    
                for u, v in self.graph.edges():
                    if (u, v) in highlight_edges:
                        f.write(f'  "{u}" -> "{v}" [color="red", penwidth=2.0];\n')
                    else:
                        f.write(f'  "{u}" -> "{v}";\n')
                        
                f.write("}\n")
                self.logger.info(f"Exported Call Graph DOT to {output_path}")
        except Exception as e:
            self.logger.error(f"Failed to export DOT file: {e}")
