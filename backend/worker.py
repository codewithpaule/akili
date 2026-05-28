import os
import time
import json
import logging
from typing import Generator

from dotenv import load_dotenv
load_dotenv()

from agent import run_agent
from database import append_scan_log, save_scan

logger = logging.getLogger('akili.worker')


def run_agent_job(module: str, target: str, scan_id: str, user_id: str = '', scan_tier: str = 'trial'):
    """Background job wrapper that runs the agent and persists logs to DB."""
    try:
        for chunk in run_agent(module, target, scan_id, lite=False, user_id=user_id, scan_tier=scan_tier):
            # chunk is a string line like '[TOOL] ...' or 'COMPLETE:...'
            try:
                if isinstance(chunk, str):
                    # stream line -> parse kind and message
                    if chunk.startswith('COMPLETE:'):
                        # final report
                        try:
                            report = json.loads(chunk[len('COMPLETE:'):])
                            save_scan(scan_id, module, target, report, user_id=user_id)
                            append_scan_log(scan_id, 'DONE', 'Report ready')
                        except Exception:
                            append_scan_log(scan_id, 'CRITICAL', 'Failed to parse COMPLETE payload')
                    else:
                        # try to split [KIND] message
                        m = chunk.strip()
                        kind = ''
                        msg = m
                        if m.startswith('['):
                            try:
                                k, rest = m.split(']', 1)
                                kind = k.strip('[').strip()
                                msg = rest.strip() if rest else ''
                            except Exception:
                                pass
                        append_scan_log(scan_id, kind or 'AKILI', msg)
            except Exception:
                logger.exception('Error writing scan log')
        # completed
    except Exception:
        logger.exception('run_agent_job failed')
*** End Patch