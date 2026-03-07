"""
SOFuzz - Main Mutator
Orchestrates mutation strategies
"""

import random
from typing import List, Dict, Optional, Callable, Tuple
from dataclasses import dataclass, field

from ..utils.logger import get_logger
from ..utils.constants import (
    INTERESTING_8,
    INTERESTING_16,
    INTERESTING_32,
    DEFAULT_MAX_MUTATIONS
)

from .strategies.bitflip import BitFlipStrategy
from .strategies.byteflip import ByteFlipStrategy
from .strategies.arithmetic import ArithmeticStrategy
from .strategies.interesting import InterestingValueStrategy
from .strategies.block import BlockStrategy
from .strategies.dictionary import DictionaryStrategy


@dataclass
class MutationResult:
    """Result of a mutation"""
    original_size: int
    mutated_size: int
    mutations_applied: int
    strategies_used: List[str] = field(default_factory=list)


class Mutator:
    """
    Main mutation engine
    """
    
    def __init__(
        self,
        max_mutations: int = DEFAULT_MAX_MUTATIONS,
        strategies: Dict[str, int] = None,
        dictionary_path: Optional[str] = None
    ):
        self.max_mutations = max_mutations
        self.logger = get_logger()
        
        self.bitflip = BitFlipStrategy()
        self.byteflip = ByteFlipStrategy()
        self.arithmetic = ArithmeticStrategy()
        self.interesting = InterestingValueStrategy()
        self.block = BlockStrategy()
        self.dictionary = DictionaryStrategy(dictionary_path)
        
        self.strategy_weights = strategies or {
            'bitflip': 20,
            'byteflip': 20,
            'arithmetic': 15,
            'interesting': 20,
            'block': 15,
            'dictionary': 10,
        }
        
        self._build_strategy_list()
    
    def _build_strategy_list(self) -> None:
        """Build weighted strategy list"""
        self.strategies: List[Tuple[str, Callable]] = []
        
        strategy_map = {
            'bitflip': self.bitflip.mutate,
            'byteflip': self.byteflip.mutate,
            'arithmetic': self.arithmetic.mutate,
            'interesting': self.interesting.mutate,
            'block': self.block.mutate,
            'dictionary': self.dictionary.mutate,
        }
        
        for name, weight in self.strategy_weights.items():
            if name in strategy_map:
                for _ in range(weight):
                    self.strategies.append((name, strategy_map[name]))
    
    def mutate(self, data: bytes, num_mutations: int = None) -> bytes:
        """Mutate input data"""
        if not data:
            return data
        
        mutated = bytearray(data)
        
        if num_mutations is None:
            num_mutations = random.randint(1, self.max_mutations)
        
        for _ in range(num_mutations):
            if not self.strategies:
                break
            
            strategy_name, strategy_func = random.choice(self.strategies)
            
            try:
                mutated = strategy_func(mutated)
            except Exception as e:
                self.logger.debug(f"Mutation failed ({strategy_name}): {e}")
                continue
        
        return bytes(mutated)
    
    def mutate_with_info(self, data: bytes, num_mutations: int = None) -> Tuple[bytes, MutationResult]:
        """Mutate input data and return mutation info"""
        if not data:
            return data, MutationResult(0, 0, 0)
        
        mutated = bytearray(data)
        strategies_used = []
        
        if num_mutations is None:
            num_mutations = random.randint(1, self.max_mutations)
        
        mutations_applied = 0
        
        for _ in range(num_mutations):
            if not self.strategies:
                break
            
            strategy_name, strategy_func = random.choice(self.strategies)
            
            try:
                mutated = strategy_func(mutated)
                strategies_used.append(strategy_name)
                mutations_applied += 1
            except Exception:
                continue
        
        result = MutationResult(
            original_size=len(data),
            mutated_size=len(mutated),
            mutations_applied=mutations_applied,
            strategies_used=strategies_used
        )
        
        return bytes(mutated), result
    
    def generate_variants(self, data: bytes, count: int = 10) -> List[bytes]:
        """Generate multiple variants of input"""
        variants = []
        
        for _ in range(count):
            variant = self.mutate(data)
            variants.append(variant)
        
        return variants
    
    def set_strategy_weight(self, strategy_name: str, weight: int) -> None:
        """Set weight for a strategy"""
        self.strategy_weights[strategy_name] = weight
        self._build_strategy_list()
    
    def disable_strategy(self, strategy_name: str) -> None:
        """Disable a mutation strategy"""
        if strategy_name in self.strategy_weights:
            self.strategy_weights[strategy_name] = 0
            self._build_strategy_list()
    
    def enable_strategy(self, strategy_name: str, weight: int = 10) -> None:
        """Enable a mutation strategy"""
        self.strategy_weights[strategy_name] = weight
        self._build_strategy_list()
    
    def get_strategy_stats(self) -> Dict[str, int]:
        """Get current strategy weights"""
        return self.strategy_weights.copy()
    
    def load_dictionary(self, dictionary_path: str) -> None:
        """Load dictionary file"""
        self.dictionary.load(dictionary_path)
    
    def add_dictionary_token(self, token: bytes) -> None:
        """Add a token to the dictionary"""
        self.dictionary.add_token(token)