#!/usr/bin/env python3
"""Install a Civic Infrastructure node on one Ubuntu LTS host (RFC-0002).

Normally started by INSTALL/install.sh. Standard library only: it runs on a
freshly installed Ubuntu Server before anything else is present.

Every step first inspects what exists. Missing pieces are created; matching
pieces are reused; anything that exists but does not match is reported and
the installer stops without changing it. Re-running is therefore safe.
"""

from __future__ import annotations

import argparse
import hashlib
import io
import ipaddress
import json
import os
import re
import shlex
import subprocess
import sys
import tarfile
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable, Sequence


LXC = "/snap/bin/lxc"
LXD = "/snap/bin/lxd"
SUPPORTED_UBUNTU = {"24.04"}

POOL = "civic"
THINPOOL = "civic-thinpool"
BRIDGE = "civicbr0"
PROFILE = "civic"
PORTAL = "portal"
ORCHESTRATOR = "orchestrator"
ORCHESTRATOR_PORT = 8045

MIN_LVM_POOL_GIB = 20
DEFAULT_POOL_FRACTION = 0.75

APP = "/opt/civic-orchestrator"
VENV_PY = f"{APP}/venv/bin/python"
CREDENTIAL = "/etc/civic-orchestrator/credentials/adapter.json"
SETUP = f"{APP}/current/INSTALL/container/setup.sh"
LID_DROPIN = Path("/etc/systemd/logind.conf.d/10-civic-lid.conf")


class InstallError(RuntimeError):
    pass


# --------------------------------------------------------------------- runner

@dataclass
class Result:
    returncode: int
    stdout: bytes = b""
    stderr: bytes = b""

    @property
    def text(self) -> str:
        return self.stdout.decode("utf-8", "replace").strip()

    @property
    def ok(self) -> bool:
        return self.returncode == 0


class Runner:
    """Runs commands. Inspection commands always run; changes can be dry-run."""

    def __init__(self, *, dry_run: bool = False, log: Callable[[str], None] = print) -> None:
        self.dry_run = dry_run
        self.log = log

    def query(self, argv: Sequence[str], *, input: bytes | None = None) -> Result:
        try:
            proc = subprocess.run(list(argv), input=input, capture_output=True)
        except FileNotFoundError:
            # A tool that is not installed yet means "not present".
            return Result(127, b"", f"{argv[0]}: not found".encode())
        return Result(proc.returncode, proc.stdout, proc.stderr)

    def change(self, argv: Sequence[str], *, input: bytes | None = None, quiet: bool = False) -> Result:
        if not quiet:
            self.log("  $ " + " ".join(shlex.quote(a) for a in argv))
        if self.dry_run:
            return Result(0)
        try:
            proc = subprocess.run(list(argv), input=input, capture_output=True)
        except FileNotFoundError as exc:
            raise InstallError(f"required command is not installed: {argv[0]}") from exc
        result = Result(proc.returncode, proc.stdout, proc.stderr)
        if not result.ok:
            detail = (proc.stderr or proc.stdout).decode("utf-8", "replace").strip()
            raise InstallError(f"command failed ({proc.returncode}): {argv[0]} ... {detail[-2000:]}")
        return result

    def sleep(self, seconds: float) -> None:
        if not self.dry_run:
            time.sleep(seconds)


# --------------------------------------------------------------------- config

@dataclass(frozen=True)
class NodeConfig:
    source: Path
    subnet: ipaddress.IPv4Network
    storage: str = "auto"            # auto | lvm | dir
    pool_size_gib: int | None = None
    image: str = "ubuntu:24.04"
    civicmin_repo: str | None = None
    civicmin_ref: str | None = None
    operator: str = "operator:root"

    @property
    def gateway(self) -> ipaddress.IPv4Address:
        return self.subnet.network_address + 1

    @property
    def portal_ip(self) -> ipaddress.IPv4Address:
        return self.subnet.network_address + 10

    @property
    def orchestrator_ip(self) -> ipaddress.IPv4Address:
        return self.subnet.network_address + 20

    @property
    def orchestrator_url(self) -> str:
        return f"http://{self.orchestrator_ip}:{ORCHESTRATOR_PORT}"


def parse_os_release(text: str) -> dict[str, str]:
    values: dict[str, str] = {}
    for line in text.splitlines():
        if "=" in line and not line.startswith("#"):
            key, _, value = line.partition("=")
            values[key.strip()] = value.strip().strip('"')
    return values


def check_os(os_release: dict[str, str]) -> None:
    if os_release.get("ID") != "ubuntu" or os_release.get("VERSION_ID") not in SUPPORTED_UBUNTU:
        found = f"{os_release.get('ID', '?')} {os_release.get('VERSION_ID', '?')}"
        raise InstallError(
            f"unsupported operating system: {found}; supported: Ubuntu "
            + ", ".join(sorted(SUPPORTED_UBUNTU)) + " LTS"
        )


def check_subnet(subnet: ipaddress.IPv4Network, routes: list[dict]) -> None:
    if subnet.prefixlen > 27 or not subnet.is_private:
        raise InstallError(f"bridge subnet must be a private /27 or larger: {subnet}")
    for route in routes:
        dst = route.get("dst")
        dev = route.get("dev")
        if not dst or dst == "default" or dev == BRIDGE:
            continue
        try:
            other = ipaddress.ip_network(dst, strict=False)
        except ValueError:
            continue
        if other.version == 4 and other.overlaps(subnet):
            raise InstallError(
                f"bridge subnet {subnet} overlaps an existing route {dst} on {dev}; "
                "choose another with --subnet"
            )


def gib_from_bytes(text: str) -> int:
    value = text.strip().rstrip("B").strip()
    return int(float(value)) // (1024 ** 3)


def plan_pool_size(free_gib: int, requested: int | None) -> int:
    if requested is not None:
        if requested > free_gib:
            raise InstallError(f"requested pool size {requested} GiB exceeds {free_gib} GiB free")
        return requested
    return int(free_gib * DEFAULT_POOL_FRACTION)


def source_tarball(source: Path) -> bytes:
    """The installed tree: everything except VCS metadata and build output."""
    skip_dirs = {".git", "__pycache__", "build", ".venv", ".pytest_cache"}
    buffer = io.BytesIO()
    with tarfile.open(fileobj=buffer, mode="w") as tar:
        for path in sorted(source.rglob("*")):
            rel = path.relative_to(source)
            if any(part in skip_dirs or part.endswith(".egg-info") for part in rel.parts):
                continue
            info = tar.gettarinfo(str(path), arcname=str(rel))
            info.uid = info.gid = 0
            info.uname = info.gname = "root"
            info.mode &= 0o755
            if path.is_file():
                with path.open("rb") as handle:
                    tar.addfile(info, handle)
            elif path.is_dir():
                tar.addfile(info)
    return buffer.getvalue()


def release_id(source: Path, runner: Runner) -> str:
    rev = runner.query(["git", "-C", str(source), "rev-parse", "--short=12", "HEAD"])
    if rev.ok and rev.text:
        return rev.text
    return hashlib.sha256(source_tarball(source)).hexdigest()[:12]


# -------------------------------------------------------------------- steps

@dataclass
class Installer:
    config: NodeConfig
    runner: Runner
    log: Callable[[str], None] = print
    os_release_path: Path = Path("/etc/os-release")
    lid_path: Path = Path("/proc/acpi/button/lid")
    require_root: bool = True
    notes: list[str] = field(default_factory=list)

    def lxc(self, *args: str) -> list[str]:
        return [LXC, *args]

    def exec_in(self, name: str, *argv: str) -> list[str]:
        return self.lxc("exec", name, "--", *argv)

    # -- preflight

    def preflight(self) -> None:
        self.log("== Preflight")
        if self.require_root and os.geteuid() != 0 and not self.runner.dry_run:
            raise InstallError("run the installer as root (sudo)")
        check_os(parse_os_release(self.os_release_path.read_text(encoding="utf-8")))
        if not (self.config.source / "src" / "civic_orchestrator").is_dir():
            raise InstallError(f"not a kane-orchestrator source tree: {self.config.source}")
        routes = self.runner.query(["ip", "-j", "-4", "route", "show"])
        check_subnet(self.config.subnet, json.loads(routes.text or "[]") if routes.ok else [])
        self.log(f"   Ubuntu OK, source {self.config.source}, bridge subnet {self.config.subnet}")

    # -- host

    def host(self) -> None:
        self.log("== Host packages")
        self.runner.change(["apt-get", "-o", "DPkg::Lock::Timeout=600", "update", "-q"])
        self.runner.change([
            "apt-get", "-o", "DPkg::Lock::Timeout=600", "install", "-y", "-q",
            "snapd", "lvm2", "thin-provisioning-tools", "git",
        ])
        if self.lid_path.exists() and not LID_DROPIN.exists():
            self.log("   laptop lid detected: closing the lid will not suspend the node")
            self.runner.change(["mkdir", "-p", str(LID_DROPIN.parent)])
            self.runner.change(
                ["tee", str(LID_DROPIN)],
                input=b"[Login]\nHandleLidSwitch=ignore\nHandleLidSwitchExternalPower=ignore\n"
                      b"HandleLidSwitchDocked=ignore\n",
                quiet=False,
            )
            self.notes.append("Lid-close suspend is disabled; it takes effect after the next reboot.")

    def lxd(self) -> None:
        self.log("== LXD")
        if self.runner.query(["snap", "list", "lxd"]).ok:
            self.log("   LXD already installed")
        else:
            self.runner.change(["snap", "install", "lxd"])
        self.runner.change([LXD, "waitready", "--timeout=300"])

    # -- storage

    def root_volume_group(self) -> str | None:
        source = self.runner.query(["findmnt", "-n", "-o", "SOURCE", "/"])
        if not source.ok or not source.text.startswith("/dev/"):
            return None
        vg = self.runner.query(["lvs", "--noheadings", "-o", "vg_name", source.text])
        if not vg.ok or not vg.text:
            return None
        return vg.text

    def storage(self) -> None:
        self.log("== Storage pool")
        existing = self.runner.query(self.lxc("storage", "get", POOL, "source"))
        if self.runner.query(self.lxc("storage", "show", POOL)).ok:
            self.log(f"   storage pool '{POOL}' exists (source {existing.text or 'n/a'}); reusing")
            return

        mode = self.config.storage
        vg = self.root_volume_group() if mode in {"auto", "lvm"} else None
        free_gib = 0
        if vg:
            free = self.runner.query(["vgs", "--noheadings", "--units", "b", "-o", "vg_free", vg])
            free_gib = gib_from_bytes(free.text) if free.ok else 0

        if mode == "lvm" and not vg:
            raise InstallError("--storage lvm requires the root filesystem on an LVM volume group")
        if mode == "auto":
            mode = "lvm" if vg and free_gib >= MIN_LVM_POOL_GIB else "dir"

        if mode == "dir":
            self.log("   using a directory-backed pool on the root filesystem")
            self.runner.change(self.lxc("storage", "create", POOL, "dir"))
            return

        if not self.runner.query(["lvs", f"{vg}/{THINPOOL}"]).ok:
            size = plan_pool_size(free_gib, self.config.pool_size_gib)
            if size < MIN_LVM_POOL_GIB:
                raise InstallError(f"only {free_gib} GiB free in {vg}; need {MIN_LVM_POOL_GIB} GiB")
            self.log(f"   {free_gib} GiB free in {vg}; creating a {size} GiB thin pool for containers")
            self.runner.change(["lvcreate", "-y", "-L", f"{size}G", "-T", f"{vg}/{THINPOOL}"])
        self.runner.change(self.lxc(
            "storage", "create", POOL, "lvm",
            f"source={vg}", f"lvm.thinpool_name={THINPOOL}", "lvm.vg.force_reuse=true",
        ))

    # -- network and profile

    def network(self) -> None:
        self.log("== Private bridge")
        want = f"{self.config.gateway}/{self.config.subnet.prefixlen}"
        current = self.runner.query(self.lxc("network", "get", BRIDGE, "ipv4.address"))
        if self.runner.query(self.lxc("network", "show", BRIDGE)).ok:
            if current.text != want:
                raise InstallError(
                    f"bridge {BRIDGE} exists with ipv4.address={current.text!r}, expected {want}; "
                    "not changing it"
                )
            self.log(f"   bridge {BRIDGE} {want} exists; reusing")
            return
        self.runner.change(self.lxc(
            "network", "create", BRIDGE,
            f"ipv4.address={want}", "ipv4.nat=true", "ipv6.address=none",
        ))

    def profile(self) -> None:
        self.log("== Container profile")
        if not self.runner.query(self.lxc("profile", "show", PROFILE)).ok:
            self.runner.change(self.lxc("profile", "create", PROFILE))
        devices = self.runner.query(self.lxc("profile", "device", "list", PROFILE)).text.split()
        if "root" not in devices:
            self.runner.change(self.lxc(
                "profile", "device", "add", PROFILE, "root", "disk", "path=/", f"pool={POOL}"))
        if "eth0" not in devices:
            self.runner.change(self.lxc(
                "profile", "device", "add", PROFILE, "eth0", "nic", f"network={BRIDGE}", "name=eth0"))

    # -- containers

    def container(self, name: str, address: ipaddress.IPv4Address) -> None:
        self.log(f"== Container {name} ({address})")
        if self.runner.query(self.lxc("info", name)).ok:
            current = self.runner.query(self.lxc("config", "device", "get", name, "eth0", "ipv4.address"))
            if current.text != str(address):
                raise InstallError(
                    f"container {name} exists with eth0 ipv4.address={current.text!r}, "
                    f"expected {address}; not changing it"
                )
            self.log("   exists; reusing")
        else:
            self.runner.change(self.lxc("init", self.config.image, name, "--profile", PROFILE))
            self.runner.change(self.lxc(
                "config", "device", "override", name, "eth0", f"ipv4.address={address}"))
            self.runner.change(self.lxc("config", "set", name, "boot.autostart=true"))

        state = self.runner.query(self.lxc("list", name, "-c", "s", "--format", "csv"))
        if state.text.upper() != "RUNNING":
            self.runner.change(self.lxc("start", name))
        self.wait_for_address(name, address)

    def wait_for_address(self, name: str, address: ipaddress.IPv4Address, timeout: float = 180) -> None:
        if self.runner.dry_run:
            return
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            listing = self.runner.query(self.lxc("list", name, "-c", "4", "--format", "csv"))
            if str(address) in listing.text:
                self.runner.query(self.exec_in(name, "systemctl", "is-system-running", "--wait"))
                return
            self.runner.sleep(3)
        raise InstallError(f"container {name} did not get {address} within {int(timeout)} s")

    # -- code

    def deploy_source(self, name: str, release: str, tarball: bytes) -> None:
        target = f"{APP}/releases/{release}"
        self.log(f"   installing release {release} into {name}")
        self.runner.change(self.exec_in(name, "mkdir", "-p", target), quiet=True)
        self.runner.change(self.exec_in(name, "tar", "-x", "-C", target, "-f", "-"),
                           input=tarball, quiet=True)
        self.runner.change(self.exec_in(name, "ln", "-sfn", target, f"{APP}/current"), quiet=True)

    def setup(self, name: str, *args: str) -> None:
        self.runner.change(self.exec_in(name, "bash", SETUP, *args))

    # -- credential

    def credential(self) -> None:
        self.log("== Adapter credential (broker <-> Orchestrator)")
        have = self.runner.query(self.exec_in(ORCHESTRATOR, "test", "-s", CREDENTIAL)).ok
        if not have:
            self.runner.change(self.exec_in(ORCHESTRATOR, "install", "-d", "-m", "0700",
                                            "/etc/civic-orchestrator/credentials"))
            self.runner.change(self.exec_in(
                ORCHESTRATOR, VENV_PY, "-m", "civic_orchestrator.credentials",
                "adapter", "--output", CREDENTIAL))
        else:
            self.log("   Orchestrator already holds a credential; keeping it")

        def digest(name: str) -> str:
            result = self.runner.query(self.exec_in(name, "sha256sum", CREDENTIAL))
            return result.text.split()[0] if result.ok and result.text else ""

        if self.runner.dry_run or digest(PORTAL) != digest(ORCHESTRATOR):
            self.log("   copying the credential to the Portal container (not via the host disk)")
            content = self.runner.query(self.exec_in(ORCHESTRATOR, "cat", CREDENTIAL)).stdout
            self.runner.change(self.exec_in(PORTAL, "install", "-d", "-m", "0700",
                                            "/etc/civic-orchestrator/credentials"), quiet=True)
            self.runner.change(
                self.exec_in(PORTAL, "sh", "-c", f"umask 077; cat > {CREDENTIAL}"),
                input=content, quiet=True)
            if not self.runner.dry_run and digest(PORTAL) != digest(ORCHESTRATOR):
                raise InstallError("credential copy to the Portal container did not verify")
        else:
            self.log("   Portal copy matches")

    # -- civicmin

    def civicmin(self) -> None:
        repo, ref = self.config.civicmin_repo, self.config.civicmin_ref
        if not repo or not ref:
            self.notes.append(
                "Civicmin was not installed (no --civicmin-repo/--civicmin-ref). "
                "The Portal container is ready for it."
            )
            return
        self.log(f"== Civicmin {ref} in the Portal container")
        target = f"/opt/kane-civicmin/{ref}"
        if not self.runner.query(self.exec_in(PORTAL, "test", "-d", target)).ok:
            self.runner.change(self.exec_in(
                PORTAL, "git", "clone", "--depth", "1", "--branch", ref, repo, target))
        self.runner.change(self.exec_in(PORTAL, "bash", f"{target}/INSTALL/install.sh"))

    # -- verify

    def verify(self) -> None:
        self.log("== Verification")
        health = self.runner.query(self.exec_in(
            PORTAL, "curl", "-fsS", "-m", "5", f"{self.config.orchestrator_url}/healthz"))
        if not self.runner.dry_run and not health.ok:
            raise InstallError("the Portal container cannot reach the Orchestrator health endpoint")
        self.log(f"   Orchestrator reachable from Portal: {health.text or '(dry run)'}")
        loopback = self.runner.query(self.exec_in(
            ORCHESTRATOR, "curl", "-fsS", "-m", "3", f"http://127.0.0.1:{ORCHESTRATOR_PORT}/healthz"))
        if not self.runner.dry_run and loopback.ok:
            raise InstallError("the Orchestrator answers on loopback; it must listen on its bridge address only")
        socket_state = self.runner.query(self.exec_in(
            PORTAL, "systemctl", "is-active", "civic-custom-command-broker.socket"))
        if not self.runner.dry_run and socket_state.text != "active":
            raise InstallError("the Custom Command broker socket is not active in the Portal container")
        self.log("   broker socket active; Orchestrator bound to its bridge address only")

    # -- run

    def run(self) -> None:
        cfg = self.config
        self.preflight()
        self.host()
        self.lxd()
        self.storage()
        self.network()
        self.profile()
        self.container(ORCHESTRATOR, cfg.orchestrator_ip)
        self.container(PORTAL, cfg.portal_ip)

        release = release_id(cfg.source, self.runner)
        tarball = source_tarball(cfg.source)
        self.log("== Code and runtime")
        for name in (ORCHESTRATOR, PORTAL):
            self.deploy_source(name, release, tarball)
            self.setup(name, "base")

        self.credential()
        self.log("== Services")
        self.setup(ORCHESTRATOR, "orchestrator", str(cfg.orchestrator_ip))
        self.setup(PORTAL, "portal", cfg.orchestrator_url, cfg.operator)
        self.civicmin()
        self.verify()
        self.summary(release)

    def summary(self, release: str) -> None:
        cfg = self.config
        self.log("")
        if self.runner.dry_run:
            self.log("Dry run complete: none of the commands above were run; the node was not changed.")
            return
        self.log("Civic Infrastructure node installed.")
        self.log(f"  release        {release}")
        self.log(f"  bridge         {BRIDGE} {cfg.gateway}/{cfg.subnet.prefixlen}")
        self.log(f"  portal         {cfg.portal_ip}")
        self.log(f"  orchestrator   {cfg.orchestrator_url}")
        self.log(f"  operator       {cfg.operator}")
        for note in self.notes:
            self.log(f"  note: {note}")
        self.log("")
        self.log("Next:")
        self.log(f"  sudo lxc exec {PORTAL} -- civic-participant add <username> --create-account")
        self.log(f"  sudo lxc exec {PORTAL} -- passwd <username>")
        self.log(f"  sudo lxc exec {PORTAL} -- civic-participant grant <username> water-ants --reason \"...\"")
        self.log(f"  sudo lxc exec {PORTAL} -- civic-transport-check --participant <username>")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Install a Civic Infrastructure node.")
    parser.add_argument("--source", type=Path, default=Path(__file__).resolve().parents[1],
                        help="kane-orchestrator source tree (default: this checkout)")
    parser.add_argument("--subnet", default="10.77.0.0/24",
                        help="private bridge subnet (default 10.77.0.0/24)")
    parser.add_argument("--storage", choices=["auto", "lvm", "dir"], default="auto")
    parser.add_argument("--pool-size", type=int, metavar="GIB",
                        help="LVM thin pool size in GiB (default: 75%% of free volume-group space)")
    parser.add_argument("--image", default="ubuntu:24.04")
    parser.add_argument("--civicmin-repo")
    parser.add_argument("--civicmin-ref")
    parser.add_argument("--operator",
                        help="Owner Operator recorded on grants (default: operator:<the sudo user>)")
    parser.add_argument("--dry-run", action="store_true",
                        help="inspect and print the changes without making them")
    args = parser.parse_args(argv)

    try:
        subnet = ipaddress.IPv4Network(args.subnet, strict=True)
    except ValueError as exc:
        print(f"invalid --subnet: {exc}", file=sys.stderr)
        return 2

    operator = args.operator or f"operator:{os.environ.get('SUDO_USER') or 'root'}"
    if not re.fullmatch(r"operator:[A-Za-z0-9._@-]{1,64}", operator):
        print(f"invalid --operator: {operator}", file=sys.stderr)
        return 2

    config = NodeConfig(
        source=args.source.resolve(),
        subnet=subnet,
        storage=args.storage,
        pool_size_gib=args.pool_size,
        image=args.image,
        civicmin_repo=args.civicmin_repo,
        civicmin_ref=args.civicmin_ref,
        operator=operator,
    )
    installer = Installer(config, Runner(dry_run=args.dry_run))
    try:
        installer.run()
    except InstallError as exc:
        print(f"\ninstallation stopped: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
