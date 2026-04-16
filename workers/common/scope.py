"""
Shared scope validation helper.

Imported by recon, httpx, and nuclei workers to ensure all discovered
hostnames and endpoints stay within the authorised scope_root.
"""


def is_in_scope(hostname: str, scope_root: str) -> bool:
    """Return True if *hostname* equals or is a subdomain of *scope_root*.

    Handles wildcard prefixes (*.example.com) in scope_root gracefully.
    """
    h = hostname.lower().strip()
    s = scope_root.lower().strip().lstrip("*.")
    return h == s or h.endswith(f".{s}")
