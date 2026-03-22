"""Deterministic tool-name normalization for AgentGuard.

This keeps policy behavior stable while allowing multiple agent/framework
tool names to resolve to the same internal capability.
"""

from __future__ import annotations

from typing import Dict


_TOOL_ALIASES: Dict[str, str] = {
    "read_file": "read_file",
    "fs.read": "read_file",
    "open_document": "read_file",
    "get_file_contents": "read_file",
    "view_file": "read_file",
    "open_file": "read_file",
    "cat": "read_file",
    "send_email": "send_email",
    "mail.send": "send_email",
    "reply_email": "send_email",
    "send_message": "send_message",
    "message.send": "send_message",
    "run_command": "run_command",
    "execute_command": "execute_command",
    "shell.exec": "run_command",
    "run_shell": "run_shell",
    "shell": "shell",
    "upload_file": "upload_file",
    "file.upload": "upload_file",
    "browser_upload": "browser_upload",
    "http_post": "http_post",
    "network.post": "http_post",
    "post_request": "post_request",
    "delete_file": "delete_file",
    "remove_file": "remove_file",
    "list_dir": "list_dir",
    "filesystem.list": "list_dir",
}


_CAPABILITY_MAP: Dict[str, str] = {
    "read_file": "filesystem_read",
    "send_email": "message_send",
    "send_message": "message_send",
    "run_command": "command_execution",
    "execute_command": "command_execution",
    "run_shell": "command_execution",
    "shell": "command_execution",
    "upload_file": "external_upload",
    "browser_upload": "external_upload",
    "http_post": "network_request",
    "post_request": "network_request",
    "delete_file": "filesystem_delete",
    "remove_file": "filesystem_delete",
    "list_dir": "filesystem_list",
}


def canonicalize_tool_name(tool_name: str) -> str:
    """Return the canonical tool name used by the existing policy logic."""
    tool_lower = tool_name.lower()
    return _TOOL_ALIASES.get(tool_lower, tool_lower)


def capability_type_for_tool(tool_name: str) -> str:
    """Return a coarse capability type for the given tool."""
    canonical = canonicalize_tool_name(tool_name)
    return _CAPABILITY_MAP.get(canonical, "unknown")
