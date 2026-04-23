"""
utils/display.py - Rich-powered terminal display helpers
"""

from datetime import datetime
from rich.console import Console
from rich.panel import Panel
from rich.text import Text
from rich.table import Table
from rich import box

console = Console()


def print_banner():
    console.print("""
[bold cyan]
  ███████╗███╗   ██╗ ██████╗██████╗ ██╗   ██╗██████╗ ████████╗
  ██╔════╝████╗  ██║██╔════╝██╔══██╗╚██╗ ██╔╝██╔══██╗╚══██╔══╝
  █████╗  ██╔██╗ ██║██║     ██████╔╝ ╚████╔╝ ██████╔╝   ██║   
  ██╔══╝  ██║╚██╗██║██║     ██╔══██╗  ╚██╔╝  ██╔═══╝    ██║   
  ███████╗██║ ╚████║╚██████╗██║  ██║   ██║   ██║        ██║   
  ╚══════╝╚═╝  ╚═══╝ ╚═════╝╚═╝  ╚═╝   ╚═╝   ╚═╝        ╚═╝   
[/bold cyan][bold white]
           🔐  Encrypted Chat — End-to-End Secure Messaging
[/bold white]""")


def print_session_info(username: str, mode: str, fingerprint: str,
                       host: str, port: int, role: str):
    """Display session details and key fingerprint after connection."""
    fp_styled = Text()
    for i, segment in enumerate(fingerprint.split(":")):
        color = "green" if i % 2 == 0 else "cyan"
        fp_styled.append(segment, style=f"bold {color}")
        if i < len(fingerprint.split(":")) - 1:
            fp_styled.append(":", style="dim")

    info = (
        f"[bold]User:[/bold]        {username}\n"
        f"[bold]Role:[/bold]        {role}\n"
        f"[bold]Crypto Mode:[/bold] {mode.upper()}\n"
        f"[bold]Server:[/bold]      {host}:{port}\n"
        f"[bold]Key FP:[/bold]      "
    )

    console.print(Panel(
        Text.assemble(info, fp_styled),
        title="[bold green]✅  Secure Session Established[/bold green]",
        border_style="green",
    ))
    console.print(
        "[dim]⚠  Compare the fingerprint above with the other party "
        "to verify no man-in-the-middle attack.[/dim]\n"
    )


def print_help():
    table = Table(box=box.SIMPLE, show_header=False, padding=(0, 2))
    table.add_column("Command", style="bold cyan", width=22)
    table.add_column("Description")

    cmds = [
        ("/send <filepath>", "Send an encrypted file"),
        ("/users",           "List connected users"),
        ("/whoami",          "Show your session info"),
        ("/fingerprint",     "Display key fingerprint"),
        ("/history",         "Show this session's chat log"),
        ("/help",            "Show this help menu"),
        ("/quit",            "Disconnect from server"),
    ]
    for cmd, desc in cmds:
        table.add_row(cmd, desc)

    console.print(Panel(table, title="[bold]Available Commands[/bold]",
                        border_style="cyan"))


def fmt_message(sender: str, message: str, is_self: bool = False,
                is_system: bool = False) -> None:
    """Print a single chat message with timestamp and color."""
    ts = datetime.now().strftime("%H:%M:%S")

    if is_system:
        console.print(f"[dim]{ts}[/dim] [bold yellow]*** {message} ***[/bold yellow]")
        return

    if is_self:
        name_style = "bold blue"
        msg_style  = "white"
    else:
        name_style = "bold magenta"
        msg_style  = "bright_white"

    console.print(
        f"[dim]{ts}[/dim] [{name_style}]{sender}[/{name_style}]: "
        f"[{msg_style}]{message}[/{msg_style}]"
    )


def fmt_file_event(sender: str, filename: str, size: int,
                   received: bool = True, saved_path: str = None):
    action = "received" if received else "sent"
    size_kb = size / 1024
    msg = (
        f"[bold green]📎 File {action}:[/bold green] "
        f"[cyan]{filename}[/cyan] ({size_kb:.1f} KB)"
    )
    if saved_path:
        msg += f"\n   [dim]Saved to: {saved_path}[/dim]"
    console.print(msg)


def print_error(msg: str):
    console.print(f"[bold red]Error:[/bold red] {msg}")


def print_info(msg: str):
    console.print(f"[bold cyan]Info:[/bold cyan] {msg}")
