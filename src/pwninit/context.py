from pwninit.io import IOContext
from pwninit.helpers.pwncontext import PwnContext

ioctx: IOContext | None = None
"""A global singleton for global method handling IOContext"""
pwnctx: PwnContext | None = None
"""A global singleton for global method handling of PwnContext"""

def set_ctx(new_ctx: IOContext | PwnContext) -> None:
    """Assign the global singleton instance context configuration.

    Example:
    
        >>> ctx = IOContext(args, config)
        >>> set_ctx(ctx)
    """
    if isinstance(new_ctx, IOContext):
        global ioctx
        ioctx = new_ctx
        return
    
    if isinstance(new_ctx, PwnContext):
        global pwnctx
        pwnctx = new_ctx
        return

    log.error("Invalid context.")
    
