"""Taint engine — decoupled taint tracing with JSON rules.

Public API:
    from src.taint import load_rules
    from src.taint import FlowStep, SanitizerInfo, TaintFlow, GuardInfo, AccessPath
    from src.taint import trace_taint_flow  # available after Chunk 2
"""

from src.taint.models import (
    AccessPath,
    CrossFileHop,
    FlowStep,
    GuardInfo,
    InferredSinkSource,
    SanitizerInfo,
    TaintFlow,
)
from src.taint.rules import TaintRuleSet, LanguageRules, load_rules
from src.taint.parser_protocol import ASTNode, LanguageGrammar, Parser

__all__ = [
    "AccessPath",
    "ASTNode",
    "CrossFileHop",
    "FlowStep",
    "GuardInfo",
    "InferredSinkSource",
    "LanguageGrammar",
    "LanguageRules",
    "load_rules",
    "Parser",
    "SanitizerInfo",
    "TaintFlow",
    "TaintRuleSet",
]
