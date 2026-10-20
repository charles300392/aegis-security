"""Human approval dialog for AEGIS, implemented with Tkinter."""

import json
import tkinter as tk
from tkinter import messagebox


def request_human_approval(tool_name, arguments, assessment):
    """Ask a local human to approve one exact VALIDATE request.

    Returns True only when the user explicitly clicks Yes. If the UI cannot
    be displayed or any error occurs, the request is denied (fail closed).

    This is an application confirmation dialog, not the Windows UAC secure
    desktop. Only trusted application code should call this function.
    """
    root = None
    try:
        root = tk.Tk()
        root.withdraw()
        root.attributes("-topmost", True)

        arguments_text = json.dumps(
            arguments,
            indent=2,
            ensure_ascii=False,
            default=str,
        )
        if len(arguments_text) > 1200:
            arguments_text = arguments_text[:1200] + "\n... (truncated)"

        risk_score = assessment.get("risk_score", "Unknown")
        reason = assessment.get(
            "reason",
            "Additional validation required",
        )

        message = (
            "AEGIS has paused an action that requires your approval.\n\n"
            f"Tool: {tool_name}\n"
            f"Risk score: {risk_score}\n"
            f"Reason: {reason}\n\n"
            f"Requested arguments:\n{arguments_text}\n\n"
            "Allow this exact request to proceed?"
        )

        return messagebox.askyesno(
            title="AEGIS Security - Approval Required",
            message=message,
            icon="warning",
            default="no",
            parent=root,
        ) is True
    except Exception:
        return False
    finally:
        if root is not None:
            try:
                root.destroy()
            except Exception:
                pass
