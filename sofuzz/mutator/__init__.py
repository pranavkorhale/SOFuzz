"""
SOFuzz - Mutator Module
"""

from .mutator import Mutator
from .strategies.bitflip import BitFlipStrategy
from .strategies.byteflip import ByteFlipStrategy
from .strategies.arithmetic import ArithmeticStrategy
from .strategies.interesting import InterestingValueStrategy
from .strategies.block import BlockStrategy
from .strategies.dictionary import DictionaryStrategy