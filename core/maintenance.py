"""
Maintenance Tasks Module.

Provides periodic cleanup and maintenance functions for Flow.
"""

import logging
from django.utils import timezone

log = logging.getLogger("core.maintenance")


def cleanup_expired_blocks():
    """
    Remove expired block entries from the database.
    
    While nftables kernel automatically removes expired rules,
    this function keeps the database in sync by cleaning up
    BlockedIp records whose expires_at has passed.
    
    Should be called periodically from the app's maintenance loop.
    """
    from core.models import BlockedIp
    from core import firewall
    
    try:
        expired = BlockedIp.objects.filter(expires_at__lt=timezone.now())
        count = expired.count()
        
        for entry in expired:
            # Check policy: even if time expired, don't unblock if active alerts exist
            from core.unblock_policy import should_unblock_ip
            if not should_unblock_ip(entry.ip):
                log.info(f"Block for {entry.ip} expired but kept due to active alerts")
                continue

            # Try to unblock (may already be expired in nftables)
            try:
                firewall.unblock_ip(entry.ip)
            except Exception:
                pass  # Ignore errors, just clean DB
            entry.delete()
        
        if count > 0:
            log.info(f"Cleaned up {count} expired block entries")
            
    except Exception as e:
        log.exception(f"Error during expired block cleanup: {e}")


def run_all_maintenance():
    """
    Run all maintenance tasks.
    Called periodically by the app's background thread.
    """
    cleanup_expired_blocks()
