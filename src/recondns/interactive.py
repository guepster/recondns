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
        self.domain = domain or ""

    def preloop(self):
        loading_animation()
        # si tu veux juste un banner random, tu peux ignorer domain
        banner = pick_banner(self.domain) if self.domain else pick_banner()
        print(banner)

    # --- NOUVELLE VERSION DE help ---
    def do_help(self, arg):
        """help ou help <commande> — affiche l'aide."""
        arg = arg.strip()

        # help sans argument -> petit "man" général de la console
        if not arg:
            print("""
Commandes recondns (mode console) :

  info <domain> [options]
    Résumé DNS + passif + bruteforce.
    (options détaillées : help info)

  snapshot <domain> [options]
    Snapshot JSON complet (DNS + passif + takeover, etc.).
    (help snapshot)

  history <domain> --db data/recondns.sqlite
    Liste les snapshots d'un domaine dans SQLite.

  diff <domain> --db data/recondns.sqlite --from ID --to ID
    Compare deux snapshots en DB.

  exit / quit
    Quitter la console RECONDNS.
""")
            return

        # help <commande> -> on appelle l'aide Click de la commande
        cmd = arg.lower()
        try:
            if cmd == "info":
                info.main(args=["--help"], standalone_mode=False)
                return
            if cmd == "snapshot":
                snapshot.main(args=["--help"], standalone_mode=False)
                return
            if cmd == "history":
                history.main(args=["--help"], standalone_mode=False)
                return
            if cmd == "diff":
                diff.main(args=["--help"], standalone_mode=False)
                return
        except SystemExit:
            # Click fait un sys.exit() sur --help, on ignore pour rester dans la console
            return

        # Si ce n'est pas une commande spéciale, on laisse le help par défaut de cmd.Cmd
        return super().do_help(arg)

    def do_exit(self, arg):
        """Quitter RECONDNS."""
        print("Bye 👋")
        return True

    def do_quit(self, arg):
        """Alias de exit."""
        return self.do_exit(arg)

    def cmdloop(self, *args, **kwargs):
        try:
            super().cmdloop(*args, **kwargs)
        except KeyboardInterrupt:
            print("\nBye 👋")
            return True
    
        # ============================
    #        COMMANDES
    # ============================
    def do_info(self, arg):
        """info <domaine> [options] — lance la commande recondns info"""
        try:
            args = arg.split()
            if not args:
                print("Usage: info <domaine> [options]")
                return
            # On appelle la commande click "info"
            info.main(args=args, standalone_mode=False)
        except SystemExit:
            return

    def do_snapshot(self, arg):
        """snapshot <domaine> [options] — lance la commande snapshot"""
        try:
            args = arg.split()
            if not args:
                print("Usage: snapshot <domaine> [options]")
                return
            snapshot.main(args=args, standalone_mode=False)
        except SystemExit:
            return

    def do_history(self, arg):
        """history <domaine> --db fichier.sqlite"""
        try:
            args = arg.split()
            if not args:
                print("Usage: history <domaine> --db fichier.sqlite")
                return
            history.main(args=args, standalone_mode=False)
        except SystemExit:
            return

    def do_diff(self, arg):
        """diff <domaine> --db DB --from ID --to ID"""
        try:
            args = arg.split()
            if not args:
                print("Usage: diff <domaine> --db DB --from X --to Y")
                return
            diff.main(args=args, standalone_mode=False)
        except SystemExit:
            return



def start_console(domain: str | None = None):
    console = ReconConsole(domain=domain)
    console.cmdloop()

