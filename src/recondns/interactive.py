import cmd
import os
import random
import time

from .cli import diff, history, info, snapshot

# --- Plusieurs bannières ASCII aléatoires ---

BANNERS = [
    r"""
██████╗ ███████╗ ██████╗ ███╗   ██╗██████╗ ███╗   ██╗██████╗ 
██╔══██╗██╔════╝██╔════╝ ████╗  ██║██╔══██╗████╗  ██║██╔══██╗
██████╔╝█████╗  ██║  ███╗██╔██╗ ██║██████╔╝██╔██╗ ██║██║  ██║
██╔═══╝ ██╔══╝  ██║   ██║██║╚██╗██║██╔══██╗██║╚██╗██║██║  ██║
██║     ███████╗╚██████╔╝██║ ╚████║██║  ██║██║ ╚████║██████╔╝
╚═╝     ╚══════╝ ╚═════╝ ╚═╝  ╚═══╝╚═╝  ╚═╝╚═╝  ╚═══╝╚═════╝
                    RECONDNS — by guepster
""",
    r"""
   ____  ________   ________  _   __ ____  _   __  _____ 
  / __ \/_  __/ /  / ____/ / / /  / __ \| | / / / / /   |
 / /_/ / / / / /  / /   / /_/ /  / /_/ /| |/ / / / / /| |
/ ____/ / / / /__/ /___/ __  /  / _, _/ |   / /_/ / ___ |
/_/     /_/ /_____\____/_/ /_/  /_/ |_|  |_/\____/_/  |_|
                  recondns — dns recon & monitoring
""",
    r"""
   ██████╗ ███████╗ ██████╗ ██████╗ ███╗   ██╗██████╗ ███████╗
  ██╔════╝ ██╔════╝██╔════╝██╔═══██╗████╗  ██║██╔══██╗██╔════╝
  ██║  ███╗█████╗  ██║     ██║   ██║██╔██╗ ██║██║  ██║█████╗  
  ██║   ██║██╔══╝  ██║     ██║   ██║██║╚██╗██║██║  ██║██╔══╝  
  ╚██████╔╝███████╗╚██████╗╚██████╔╝██║ ╚████║██████╔╝███████╗
   ╚═════╝ ╚══════╝ ╚═════╝ ╚═════╝ ╚═╝  ╚═══╝╚═════╝ ╚══════╝
                 [ recondns :: attack surface watcher ]
""",
    r"""
  [ recondns ]    passive dns • subdomain enum • takeover hints
  ─────────────────────────────────────────────────────────────
         target: {{domain}}        mode: CLI
""",
]


def pick_banner(domain: str | None = None) -> str:
    """Choisit une bannière au hasard et remplace éventuellement {{domain}}."""
    banner = random.choice(BANNERS)
    if "{{domain}}" in banner and domain:
        banner = banner.replace("{{domain}}", domain)
    return banner


def wave_text(text: str) -> str:
    """Texte avec majuscules/minuscules aléatoires (effet 'vague')."""
    return "".join(c.upper() if random.random() > 0.5 else c.lower() for c in text)


def loading_animation():
    base = "Chargement de RECONDNS"
    for _ in range(12):  # 12 frames d'animation
        os.system("cls" if os.name == "nt" else "clear")
        print(wave_text(base) + "...")
        time.sleep(0.12)
    os.system("cls" if os.name == "nt" else "clear")


class ReconConsole(cmd.Cmd):
    prompt = "RECONDNS > "

    def __init__(self, domain: str | None = None):
        super().__init__()
        self.domain = domain

    def preloop(self):
        loading_animation()
        banner = pick_banner(self.domain)
        print(banner)

    def do_info(self, arg):
        """info example.com --options..."""
        import shlex

        args = shlex.split(arg)
        info.main(args=args, standalone_mode=False)

    def do_snapshot(self, arg):
        args = arg.split()
        snapshot.main(args=args, standalone_mode=False)

    def do_history(self, arg):
        args = arg.split()
        history.main(args=args, standalone_mode=False)

    def do_diff(self, arg):
        args = arg.split()
        diff.main(args=args, standalone_mode=False)

    def do_exit(self, arg):
        """Quitter la console."""
        return True

    def do_quit(self, arg):
        return True

    def emptyline(self):
        pass


def start_console(domain: str | None = None):
    ReconConsole(domain=domain).cmdloop()
