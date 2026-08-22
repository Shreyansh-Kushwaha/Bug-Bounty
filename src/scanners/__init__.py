"""Deterministic, non-LLM scanners that enrich Recon output.

Each scanner takes a cloned-repo path and returns a JSON-serializable result
that gets written as its own artifact under data/findings/<run_id>/.
"""
