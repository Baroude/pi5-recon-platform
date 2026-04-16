"""
Output file cleanup helper shared by all workers.

Each worker calls _cleanup_old_outputs() at the start of process_task()
to prevent unbounded growth of raw JSONL/TXT output on disk.
"""

import glob as _glob
import logging
import os
import time

logger = logging.getLogger(__name__)


def cleanup_old_outputs(output_dir: str, pattern: str, max_age_days: int = 7) -> int:
    """Delete files matching *pattern* inside *output_dir* older than *max_age_days*.

    Returns the number of files deleted.
    """
    cutoff = time.time() - max_age_days * 86400
    deleted = 0
    search = os.path.join(output_dir, "**", pattern)
    for path in _glob.glob(search, recursive=True):
        try:
            if os.path.isfile(path) and os.path.getmtime(path) < cutoff:
                os.remove(path)
                deleted += 1
        except OSError as exc:
            logger.warning("Could not remove old output file %s: %s", path, exc)
    if deleted:
        logger.info("Cleaned up %d old output file(s) from %s", deleted, output_dir)
    return deleted
