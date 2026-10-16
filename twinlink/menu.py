"""Numbered operator workflows which reuse the scriptable CLI and its checks."""

import os
import shlex

from .store import Store, StateError
from .rathole_groups import groups


class _Cancelled(Exception):
    pass


def _safe_command(arguments):
    """Display intent without echoing credential-shaped command arguments."""
    result = []
    hide_next = False
    private = {"--token", "--password", "--secret", "--code"}
    for argument in arguments:
        if hide_next:
            result.append("<redacted>")
            hide_next = False
        elif argument in private:
            result.append(argument)
            hide_next = True
        elif any(argument.startswith(flag + "=") for flag in private):
            result.append(argument.split("=", 1)[0] + "=<redacted>")
        else:
            result.append(argument)
    return "twinlink " + shlex.join(result)


def _global_arguments(args):
    result = []
    for field in ("state_dir", "unit_dir", "runtime_path", "rathole_binary"):
        value = getattr(args, field, None)
        if value is not None:
            result.extend(("--" + field.replace("_", "-"), str(value)))
    if getattr(args, "json", False):
        result.append("--json")
    if getattr(args, "no_systemd", False):
        result.append("--no-systemd")
    return result


class _Menu:
    def __init__(self, args, runner, read, write):
        self.globals = _global_arguments(args)
        self.state_dir = getattr(args, "state_dir", "/var/lib/twinlink")
        self.runner, self.read, self.write = runner, read, write

    def prompt(self, label, default=None, required=False):
        suffix = f" [{default}]" if default is not None else ""
        while True:
            value = self.read(label + suffix + ": ").strip()
            if value == "!":
                raise _Cancelled()
            if not value and default is not None:
                return str(default)
            if value or not required:
                return value
            self.write("A value is required. Type ! to cancel this operation.")

    def choice(self, title, choices, default=None):
        self.write("\n" + title)
        for key, label in choices:
            self.write(f"  {key}) {label}")
        valid = {str(key) for key, _ in choices}
        while True:
            value = self.prompt("Choice", default=default, required=True)
            if value in valid:
                return value
            self.write("Choose one of the displayed numbers.")

    def yes(self, label, default=False):
        while True:
            value = self.prompt(label + " (y/n)", default="y" if default else "n").lower()
            if value in ("y", "yes"):
                return True
            if value in ("n", "no"):
                return False
            self.write("Enter y or n.")

    def invoke(self, arguments):
        try:
            result = self.runner(self.globals + arguments)
            return 0 if result is None else result
        except SystemExit as exc:
            self.write("Command was rejected; review the help or values above.")
            return exc.code if isinstance(exc.code, int) else 1

    def execute(self, arguments, mutation=False, private_export=False):
        # Even expert mode cannot skip the menu's preview/confirmation step.
        apply_flags = {"--" + option[:length] for option in ("apply", "yes") for length in range(1, len(option) + 1)}
        clean = [argument for argument in arguments if argument not in apply_flags]
        self.write("\n" + _safe_command(self.globals + clean))
        if private_export:
            self.write("This explicitly writes matching forwarding configuration, including a rathole token when present, to the selected private file.")
            if self.prompt("Type export to write the file; Enter cancels").lower() != "export":
                self.write("Export cancelled.")
                return
            self.invoke(clean)
            return
        result = self.invoke(clean)
        if not mutation or result:
            return result
        if self.prompt("Review the preview above. Type apply to execute it; Enter cancels").lower() != "apply":
            self.write("Preview only; no changes applied.")
            return
        # The preceding prompt is the explicit apply confirmation, so do not
        # ask the operator to confirm the same preview a second time in CLI.
        return self.invoke(clean + ["--apply", "--yes"])

    def _rathole_tunnel(self, state):
        eligible = sorted((tunnel for tunnel in state["tunnels"].values()
                           if tunnel["verified"] and tunnel["running"]), key=lambda tunnel: tunnel["name"])
        if not eligible:
            self.write("No running, verified GRE tunnel is available. Create/pair GRE first, then start and verify it on both servers.")
            for tunnel in sorted(state["tunnels"].values(), key=lambda tunnel: tunnel["name"]):
                if not tunnel["running"]:
                    self.write(_safe_command(self.globals + ["tunnel", "start", tunnel["name"], "--apply"]))
                if not tunnel["verified"]:
                    self.write(_safe_command(self.globals + ["tunnel", "check", tunnel["name"], "--record", "--apply"]))
            return None
        sides = {tunnel["side"] for tunnel in eligible}
        if len(sides) == 1:
            side = eligible[0]["side"]
            self.write(f"Detected {side.upper()} from saved GRE configuration.")
        else:
            selected = self.choice("Saved tunnels have both roles; choose this setup's role", (
                ("1", "VPS1: create/export forwarding"), ("2", "VPS2: paste pairing text")))
            side = "vps1" if selected == "1" else "vps2"
        if side == "vps2":
            # Pairing import matches the saved mirrored GRE endpoints itself;
            # there is no reason to ask the client to choose a tunnel again.
            return {"side": side}
        tunnels = [tunnel for tunnel in eligible if tunnel["side"] == side]
        if len(tunnels) == 1:
            tunnel = tunnels[0]
        else:
            selected = self.choice("Choose a saved GRE tunnel", tuple(
                (str(index + 1), f"{tunnel['name']}: peer {tunnel['remote_public']} (GRE {tunnel['remote_private']})")
                for index, tunnel in enumerate(tunnels)))
            tunnel = tunnels[int(selected) - 1]
        self.write(f"Using tunnel {tunnel['name']}: {tunnel['local_public']} ({tunnel['local_private']}) -> "
                   f"{tunnel['remote_public']} ({tunnel['remote_private']}). Rathole connects over the saved GRE private addresses.")
        return tunnel

    def _rathole_destination(self, state, tunnel):
        saved = sorted({entry["destination_address"] for entry in state["forwards"].values()
                        if entry["tunnel"] == tunnel["name"]})
        candidates = [(address, "Saved backend") for address in saved]
        candidates += [("127.0.0.1", "VPS2 loopback"),
                       (tunnel["remote_private"].split("/", 1)[0], "VPS2 GRE private IP"),
                       (tunnel["remote_public"], "VPS2 public IP")]
        addresses = []
        for address, label in candidates:
            if address not in [item[0] for item in addresses]:
                addresses.append((address, label))
        choices = tuple((str(index + 1), f"{label}: {address}") for index, (address, label) in enumerate(addresses))
        selected = self.choice("Backend service address on/reachable from VPS2", choices + (("0", "Another IPv4 address"),), default="1")
        if selected == "0":
            return self.prompt("Other backend IPv4", required=True)
        return addresses[int(selected) - 1][0]

    def rathole_setup(self):
        from .rathole import forward_names, port_mappings
        self.write("Rathole over GRE with Noise encryption. Reusing saved tunnel names, roles and endpoints.")
        self.write("Setup installs Rathole if needed and generates credentials automatically. No editor is opened.")
        try:
            state = Store(self.state_dir).read()
        except (StateError, OSError) as exc:
            self.write("Cannot read saved configuration: " + str(exc))
            return 1
        tunnel = self._rathole_tunnel(state)
        if tunnel is None:
            return 1
        if tunnel["side"] == "vps1":
            existing = sorted(entry["name"] for entry in state["forwards"].values()
                              if entry["tunnel"] == tunnel["name"] and entry["mode"] == "rathole")
            if existing:
                selected = self.choice("Rathole forwarding already saved: " + ", ".join(existing), (
                    ("1", "Export base64 pairing text for saved forwarding"), ("2", "Add forwarding ports"),
                    ("3", "Combine saved forwarding into one Rathole config")), default="1")
                if selected == "1":
                    self.write("Pairing text contains service tokens. Transfer it privately to VPS2.")
                    return self.invoke(["rathole", "pair-export", *existing])
            combining = bool(existing) and selected == "3"
            saved_groups = [(name, entries) for name, entries in sorted(groups(state).items())
                            if entries[0]["tunnel"] == tunnel["name"]]
            chosen = None
            if saved_groups and not combining:
                if len(saved_groups) == 1:
                    chosen = saved_groups[0]
                else:
                    choice = self.choice("Add services to a saved Rathole config", tuple(
                        (str(index + 1), f"{name}: connection port {entries[0]['transport_port']}")
                        for index, (name, entries) in enumerate(saved_groups)) + (("0", "Create another named config"),))
                    if choice != "0":
                        chosen = saved_groups[int(choice) - 1]
            if chosen:
                name, entries = chosen
                transport_port = str(entries[0]["transport_port"])
                self.write(f"Reusing Rathole {name}, connection port {transport_port}.")
            else:
                name = self.prompt("Rathole name", default=tunnel["name"][:32] + "-rathole")
                while True:
                    transport_port = self.prompt("Rathole connection port", default="2333")
                    if transport_port.isascii() and transport_port.isdigit() and 1024 <= int(transport_port) <= 65535:
                        break
                    self.write("Enter one port between 1024 and 65535.")
            if combining:
                command = ["rathole", "consolidate", name, "--tunnel", tunnel["name"], "--transport-port", transport_port]
            else:
                destination = self._rathole_destination(state, tunnel)
                while True:
                    ports = self.prompt("Forwarding ports PUBLIC:BACKEND, comma separated (e.g. 8080:80,8443:443; 9000 keeps the same port)", required=True)
                    try:
                        mappings = port_mappings(ports)
                        break
                    except ValueError as exc:
                        self.write(str(exc))
                self.write("Forwarding services: " + ", ".join(forward_names(name, mappings)))
                command = ["rathole", "add", name, "--tunnel", tunnel["name"], "--transport-port", transport_port,
                           "--destination-address", destination, "--ports", ports]
        else:
            self.write("Pairing text contains service tokens. Paste it only on the intended peer.")
            code = self.prompt("Rathole base64 pairing text (r1.…)", required=True)
            command = ["rathole", "pair-import", "--code", code, "--enable"]
        binary = self.globals[self.globals.index("--rathole-binary") + 1] if "--rathole-binary" in self.globals else "/usr/local/bin/rathole"
        if not os.path.exists(binary):
            self.write("Install the official pinned Rathole release on this server:")
            installed = self.execute(["rathole", "install"], mutation=True)
            if installed != 0:
                return installed
        result = self.execute(command, mutation=True)
        if result == 0 and tunnel["side"] == "vps1":
            self.write("Copy pairing_code above to VPS2 and run: sudo twinlink rathole setup")
        return result

    def named(self, group, action, extra=(), mutation=False):
        name = self.prompt("Local " + group + " name", required=True)
        self.execute([group, action, name, *extra], mutation=mutation)

    def create_tunnel(self):
        self.write("Use public IPv4 endpoints and two private hosts in the same RFC1918 subnet. Type ! to cancel.")
        name = self.prompt("Stable tunnel name", required=True)
        side = self.choice("This server", (("1", "VPS1 (public service side)"), ("2", "VPS2 (destination side)")))
        command = ["tunnel", "create", name, "--side", "vps1" if side == "1" else "vps2"]
        for flag, label, default in (
            ("local-public", "This server's assigned public IPv4", None),
            ("remote-public", "Other server's public IPv4", None),
            ("local-private", "This server's private GRE address/prefix", None),
            ("remote-private", "Other server's private GRE address/prefix", None),
            ("mtu", "GRE MTU", "1472"), ("ttl", "GRE TTL", "64"),
            ("key", "Optional matching GRE key (Enter for none)", None),
        ):
            value = self.prompt(label, default=default, required=flag in {"local-public", "remote-public", "local-private", "remote-private"})
            if value:
                command.extend(("--" + flag, value))
        if self.yes("Create stopped and disabled at reboot"):
            command.append("--disabled")
        self.execute(command, mutation=True)

    def import_tunnel(self):
        command = ["tunnel", "pair-import", "--file", self.prompt("GRE pairing file received from the other server", required=True)]
        name = self.prompt("Local tunnel name (Enter to keep exported name)")
        if name:
            command.extend(("--name", name))
        if self.yes("Replace an existing local tunnel and stop its dependents"):
            command.append("--replace")
        self.execute(command, mutation=True)

    def add_forward(self):
        self.write("First verify GRE on both servers. Matching configuration must be transferred to the other server.")
        name = self.prompt("Stable forwarding name", required=True)
        tunnel = self.prompt("Local verified GRE tunnel name", required=True)
        mode_choice = self.choice("Forwarding mode", (("1", "Kernel TCP/UDP"), ("2", "Rathole 0.5.0 TCP")), default="1")
        mode = "kernel" if mode_choice == "1" else "rathole"
        protocol = "tcp"
        if mode == "kernel":
            selected = self.choice("Protocol", (("1", "TCP"), ("2", "UDP")), default="1")
            protocol = "tcp" if selected == "1" else "udp"
        command = ["forward", "add", name, "--tunnel", tunnel, "--mode", mode, "--protocol", protocol]
        for flag, label, required in (
            ("bind-address", "VPS1 public bind IPv4 (Enter for its GRE public endpoint)", False),
            ("bind-port", "Public bind port" + (" or range (up to 256 ports)" if mode == "kernel" else ""), True),
            ("destination-address", "Backend IPv4 reachable from VPS2", True),
            ("destination-port", "Backend port" + (" or range" if mode == "kernel" else ""), True),
            (("relay-port" if mode == "kernel" else "transport-port"), "Optional GRE relay/connection port (Enter to allocate)", False),
        ):
            value = self.prompt(label, required=required)
            if value:
                command.extend(("--" + flag, value))
        if self.yes("Create stopped and disabled while pairing", default=True):
            command.append("--disabled")
        self.execute(command, mutation=True)

    def import_forward(self):
        path = self.prompt("Private forwarding pairing file (0600, received securely)", required=True)
        self.execute(["forward", "import", "--file", path], mutation=True)

    def export_forward(self):
        name = self.prompt("Forwarding name", required=True)
        path = self.prompt("New output file in a private directory", required=True)
        self.execute(["forward", "export", name, "--output", path], private_export=True)

    def lifecycle(self, group):
        name = self.prompt("Local " + group + " name", required=True)
        actions = ("enable", "disable", "start", "stop", "restart", "reapply", "delete")
        labels = ("Enable at boot and start", "Disable at boot and stop", "Start now", "Stop now", "Restart", "Reapply to repair drift", "Delete")
        selected = self.choice("Lifecycle operation", tuple((str(index + 1), label) for index, label in enumerate(labels)) + (("0", "Back"),))
        if selected == "0":
            return
        action = actions[int(selected) - 1]
        command = [group, action, name]
        if group == "tunnel" and action == "delete":
            cascade = self.choice("Dependent forwarding entries", (("1", "Refuse deletion if dependents exist"), ("2", "Cascade: delete dependent entries too")), default="1")
            command.append("--cascade" if cascade == "2" else "--no-cascade")
        self.execute(command, mutation=True)

    def edit(self, group):
        name = self.prompt("Local " + group + " name", required=True)
        self.execute([group, "show", name])
        self.write("Enter changed values only; Enter keeps each value. Shared edits require a new pairing export/import.")
        fields = (("local-public", "remote-public", "local-private", "remote-private", "mtu", "ttl", "key")
                  if group == "tunnel" else ("protocol", "bind-address", "bind-port", "destination-address", "destination-port", "relay-port", "transport-port"))
        command = [group, "edit", name]
        for field in fields:
            value = self.prompt(field)
            if value:
                command.extend(("--" + field, value))
        if group == "tunnel" and self.yes("Clear the GRE key"):
            command.append("--clear-key")
        if len(command) == 3:
            self.write("No edits selected.")
            return
        self.execute(command, mutation=True)

    def tunnels(self):
        while True:
            selected = self.choice("GRE tunnels", (
                ("1", "List tunnels and health"), ("2", "Create GRE tunnel"),
                ("3", "Export GRE pairing code"), ("4", "Import GRE pairing file"),
                ("5", "Check peer and record successful verification"), ("6", "Diagnose tunnel"),
                ("7", "Enable/disable/start/stop/restart/reapply/delete"), ("8", "Edit tunnel"), ("0", "Back")))
            if selected == "0":
                return
            try:
                if selected == "1":
                    self.execute(["tunnel", "list"])
                elif selected == "2":
                    self.create_tunnel()
                elif selected == "3":
                    self.named("tunnel", "pair-export")
                elif selected == "4":
                    self.import_tunnel()
                elif selected == "5":
                    self.named("tunnel", "check", extra=("--record",), mutation=True)
                elif selected == "6":
                    self.named("tunnel", "diagnose")
                elif selected == "7":
                    self.lifecycle("tunnel")
                else:
                    self.edit("tunnel")
            except _Cancelled:
                self.write("Operation cancelled.")

    def forwards(self):
        while True:
            selected = self.choice("Forwarding entries", (
                ("1", "List entries and health"), ("2", "Add forwarding entry"),
                ("3", "Import private forwarding file"), ("4", "Export private forwarding file"),
                ("5", "Check forwarding health"), ("6", "Diagnose forwarding"),
                ("7", "Enable/disable/start/stop/restart/reapply/delete"), ("8", "Edit entry"), ("0", "Back")))
            if selected == "0":
                return
            try:
                if selected == "1":
                    self.execute(["forward", "list"])
                elif selected == "2":
                    self.add_forward()
                elif selected == "3":
                    self.import_forward()
                elif selected == "4":
                    self.export_forward()
                elif selected == "5":
                    self.named("forward", "check")
                elif selected == "6":
                    self.named("forward", "diagnose")
                elif selected == "7":
                    self.lifecycle("forward")
                else:
                    self.edit("forward")
            except _Cancelled:
                self.write("Operation cancelled.")

    def expert(self):
        self.write("Enter a twinlink subcommand without a shell or global options. Mutations still preview first.")
        try:
            command = shlex.split(self.prompt("Subcommand", required=True))
        except ValueError as exc:
            self.write("Invalid command quoting: " + str(exc))
            return
        if not command or command[0] not in {"tunnel", "forward", "rathole", "doctor", "status", "recover", "uninstall"}:
            self.write("Choose a tunnel, forward, rathole, doctor, status, recover or uninstall subcommand.")
            return
        action = command[1] if len(command) > 1 else ""
        mutation = ((command[0] in {"tunnel", "forward"} and action in {"create", "add", "edit", "pair-import", "import", "enable", "disable", "start", "stop", "restart", "reapply", "delete"})
                    or (command[0] == "rathole" and action in {"install", "add", "consolidate", "pair-import"})
                    or command[0] == "recover" or (command[0] == "uninstall" and "--purge-managed" in command)
                    or (command[0] == "tunnel" and action == "check" and "--record" in command))
        self.execute(command, mutation=mutation, private_export=command[:2] == ["forward", "export"])

    def run(self):
        self.write("twinLink operator menu. Type ! at a prompt to cancel an operation.")
        while True:
            selected = self.choice("Main menu", (
                ("1", "Overview and live health"), ("2", "GRE tunnels"), ("3", "Forwarding entries"),
                ("4", "Dependency doctor"), ("5", "Recover interrupted transaction"),
                ("6", "Expert CLI subcommand"), ("7", "Rathole installation and Noise setup"),
                ("8", "Rathole config paths and editor commands"), ("0", "Exit")))
            if selected == "0":
                return 0
            try:
                if selected == "1":
                    self.execute(["status"])
                elif selected == "2":
                    self.tunnels()
                elif selected == "3":
                    self.forwards()
                elif selected == "4":
                    self.execute(["doctor"])
                elif selected == "5":
                    self.execute(["recover"], mutation=True)
                elif selected == "7":
                    self.rathole_setup()
                elif selected == "8":
                    self.named("rathole", "config")
                else:
                    self.expert()
            except _Cancelled:
                self.write("Operation cancelled.")


def run_menu(args, command_runner=None, input_fn=None, output_fn=None):
    """Run guided operations, preserving the CLI's global installation paths."""
    if command_runner is None:
        from .cli import main
        command_runner = main
    menu = _Menu(args, command_runner, input_fn or input, output_fn or print)
    try:
        return menu.run()
    except (EOFError, KeyboardInterrupt, _Cancelled):
        menu.write("\nMenu closed.")
        return 0


def run_rathole_setup(args, command_runner=None, input_fn=None, output_fn=None):
    if command_runner is None:
        from .cli import main
        command_runner = main
    menu = _Menu(args, command_runner, input_fn or input, output_fn or print)
    try:
        return menu.rathole_setup() or 0
    except (EOFError, KeyboardInterrupt, _Cancelled):
        menu.write("\nSetup cancelled.")
        return 0
