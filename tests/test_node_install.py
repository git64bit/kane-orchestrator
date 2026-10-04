"""Installer decision tests with a fake command runner (no LXD required)."""

import importlib.util
import io
import ipaddress
import sys
import tarfile
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
_spec = importlib.util.spec_from_file_location("node_install", ROOT / "INSTALL" / "node_install.py")
ni = importlib.util.module_from_spec(_spec)
sys.modules["node_install"] = ni
_spec.loader.exec_module(ni)

LXC = ni.LXC
CRED = ni.CREDENTIAL


class FakeHost(ni.Runner):
    """Simulates a host. `state` describes what already exists."""

    def __init__(self, **state):
        super().__init__(dry_run=False, log=lambda _msg: None)
        self.changes = []
        self.lxd_installed = state.get("lxd_installed", False)
        self.root_source = state.get("root_source", "/dev/mapper/ubuntu--vg-ubuntu--lv")
        self.vg = state.get("vg", "ubuntu-vg")
        self.vg_free_gib = state.get("vg_free_gib", 363)
        self.thinpool = state.get("thinpool", False)
        self.pool = state.get("pool", False)
        self.bridge = state.get("bridge")            # ipv4.address or None
        self.profile = state.get("profile", False)
        self.profile_devices = set(state.get("profile_devices", ()))
        self.containers = dict(state.get("containers", {}))  # name -> {"ip":..., "running":bool}
        self.credentials = dict(state.get("credentials", {}))  # name -> digest
        self.routes = state.get("routes", [])
        self.loopback_answers = state.get("loopback_answers", False)

    # -- inspection
    def query(self, argv, *, input=None):
        a = list(argv)
        R = ni.Result
        if a[:2] == ["ip", "-j"]:
            import json
            return R(0, json.dumps(self.routes).encode())
        if a == ["snap", "list", "lxd"]:
            return R(0 if self.lxd_installed else 1)
        if a[:1] == ["git"]:
            return R(0, b"abc123def456\n")
        if a[:1] == ["findmnt"]:
            return R(0, (self.root_source + "\n").encode())
        if a[:1] == ["lvs"] and "vg_name" in a:
            return R(0, f"  {self.vg}\n".encode()) if self.vg else R(5)
        if a[:1] == ["lvs"]:
            return R(0 if self.thinpool else 5)
        if a[:1] == ["vgs"]:
            return R(0, f"  {self.vg_free_gib * 1024 ** 3}B\n".encode())
        if a[:3] == [LXC, "storage", "show"]:
            return R(0 if self.pool else 1)
        if a[:3] == [LXC, "storage", "get"]:
            return R(0, b"ubuntu-vg") if self.pool else R(1)
        if a[:3] == [LXC, "network", "show"]:
            return R(0 if self.bridge else 1)
        if a[:3] == [LXC, "network", "get"]:
            return R(0, (self.bridge or "").encode()) if self.bridge else R(1)
        if a[:3] == [LXC, "profile", "show"]:
            return R(0 if self.profile else 1)
        if a[:4] == [LXC, "profile", "device", "list"]:
            return R(0, "\n".join(sorted(self.profile_devices)).encode())
        if a[:2] == [LXC, "info"]:
            return R(0 if a[2] in self.containers else 1)
        if a[:4] == [LXC, "config", "device", "get"]:
            c = self.containers.get(a[4])
            return R(0, c["ip"].encode()) if c else R(1)
        if a[:2] == [LXC, "list"] and a[4] == "s":
            c = self.containers.get(a[2], {})
            return R(0, b"RUNNING" if c.get("running") else b"STOPPED")
        if a[:2] == [LXC, "list"] and a[4] == "4":
            c = self.containers.get(a[2], {})
            return R(0, f"{c.get('ip')} (eth0)".encode() if c.get("running") else b"")
        if a[:2] == [LXC, "exec"]:
            name, cmd = a[2], a[4:]
            if cmd[:2] == ["test", "-s"]:
                return R(0 if name in self.credentials else 1)
            if cmd[:1] == ["sha256sum"]:
                d = self.credentials.get(name)
                return R(0, f"{d}  {CRED}\n".encode()) if d else R(1)
            if cmd[:1] == ["cat"]:
                return R(0, b'{"version":1}')
            if cmd[:1] == ["curl"]:
                if "127.0.0.1" in cmd[-1]:
                    return R(0 if self.loopback_answers else 7)
                return R(0, b'{"status":"ok"}')
            if cmd[:2] == ["systemctl", "is-active"]:
                return R(0, b"active")
            if cmd[:1] == ["test"]:
                return R(1)
            return R(0)
        return R(1)

    # -- changes
    def change(self, argv, *, input=None, quiet=False):
        a = list(argv)
        self.changes.append(a)
        if a[:2] == ["snap", "install"]:
            self.lxd_installed = True
        elif a[:1] == ["lvcreate"]:
            self.thinpool = True
        elif a[:3] == [LXC, "storage", "create"]:
            self.pool = True
        elif a[:3] == [LXC, "network", "create"]:
            self.bridge = a[4].split("=", 1)[1]
        elif a[:3] == [LXC, "profile", "create"]:
            self.profile = True
        elif a[:4] == [LXC, "profile", "device", "add"]:
            self.profile_devices.add(a[5])
        elif a[:2] == [LXC, "init"]:
            self.containers[a[3]] = {"ip": None, "running": False}
        elif a[:4] == [LXC, "config", "device", "override"]:
            self.containers[a[4]]["ip"] = a[6].split("=", 1)[1]
        elif a[:2] == [LXC, "start"]:
            self.containers[a[2]]["running"] = True
        elif a[:2] == [LXC, "exec"]:
            name, cmd = a[2], a[4:]
            if "civic_orchestrator.credentials" in cmd:
                self.credentials[name] = "d1"
            elif cmd[:2] == ["sh", "-c"] and CRED in cmd[2]:
                self.credentials[name] = self.credentials.get("orchestrator")
        return ni.Result(0)

    def sleep(self, seconds):
        pass

    def has(self, *prefix):
        return any(c[:len(prefix)] == list(prefix) for c in self.changes)

    def index(self, *prefix):
        for i, c in enumerate(self.changes):
            if c[:len(prefix)] == list(prefix):
                return i
        raise AssertionError(f"no change starting with {prefix}")


class InstallerTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.os_release = Path(self.tmp.name) / "os-release"
        self.os_release.write_text('ID=ubuntu\nVERSION_ID="24.04"\n')
        self.no_lid = Path(self.tmp.name) / "no-lid"

    def tearDown(self):
        self.tmp.cleanup()

    def installer(self, host, **config):
        cfg = ni.NodeConfig(
            source=ROOT,
            subnet=ipaddress.IPv4Network(config.pop("subnet", "10.77.0.0/24")),
            **config,
        )
        return ni.Installer(
            cfg, host, log=lambda _m: None,
            os_release_path=self.os_release, lid_path=self.no_lid, require_root=False,
        )

    def test_fresh_host_builds_the_whole_node_in_order(self):
        host = FakeHost()
        self.installer(host).run()

        self.assertTrue(host.has("snap", "install", "lxd", "--channel=5.21/stable"))
        self.assertTrue(host.has("lvcreate", "-y", "-L", "272G", "-T", "ubuntu-vg/civic-thinpool"))
        self.assertTrue(host.has(LXC, "storage", "create", "civic", "lvm", "source=ubuntu-vg",
                                 "lvm.thinpool_name=civic-thinpool", "lvm.vg.force_reuse=true"))
        self.assertTrue(host.has(LXC, "network", "create", "civicbr0", "ipv4.address=10.77.0.1/24",
                                 "ipv4.nat=true", "ipv6.address=none"))
        self.assertTrue(host.has(LXC, "init", "ubuntu:24.04", "orchestrator", "--profile", "civic"))
        self.assertTrue(host.has(LXC, "config", "device", "override", "orchestrator", "eth0",
                                 "ipv4.address=10.77.0.20"))
        self.assertTrue(host.has(LXC, "config", "device", "override", "portal", "eth0",
                                 "ipv4.address=10.77.0.10"))

        setup = ni.SETUP
        base_o = host.index(LXC, "exec", "orchestrator", "--", "bash", setup, "base")
        base_p = host.index(LXC, "exec", "portal", "--", "bash", setup, "base")
        cred = host.index(LXC, "exec", "orchestrator", "--", ni.VENV_PY, "-m", "civic_orchestrator.credentials")
        orch = host.index(LXC, "exec", "orchestrator", "--", "bash", setup, "orchestrator", "10.77.0.20")
        portal = host.index(LXC, "exec", "portal", "--", "bash", setup, "portal", "http://10.77.0.20:8045",
                            "operator:root")
        self.assertLess(base_o, cred)
        self.assertLess(base_p, cred)
        self.assertLess(cred, orch)
        self.assertLess(orch, portal)
        self.assertEqual(host.credentials["portal"], host.credentials["orchestrator"])

    def test_publication_is_never_required(self):
        host = FakeHost()
        self.installer(host).run()
        flat = " ".join(" ".join(c) for c in host.changes)
        self.assertNotIn("publication", flat)
        unit = (ROOT / "INSTALL" / "systemd" / "civic-orchestrator.service").read_text()
        self.assertNotIn("publication", unit.split("[Service]", 1)[1])

    def test_rerun_on_installed_node_creates_nothing(self):
        host = FakeHost(
            lxd_installed=True, thinpool=True, pool=True, bridge="10.77.0.1/24",
            profile=True, profile_devices={"root", "eth0"},
            containers={"orchestrator": {"ip": "10.77.0.20", "running": True},
                        "portal": {"ip": "10.77.0.10", "running": True}},
            credentials={"orchestrator": "d1", "portal": "d1"},
        )
        self.installer(host).run()
        for prefix in (("snap", "install"), ("lvcreate",), (LXC, "storage", "create"),
                       (LXC, "network", "create"), (LXC, "profile", "create"),
                       (LXC, "init"), (LXC, "start")):
            self.assertFalse(host.has(*prefix), prefix)
        self.assertFalse(any("civic_orchestrator.credentials" in c for c in host.changes))
        self.assertFalse(any(c[:4] == [LXC, "exec", "portal", "--"] and c[4:6] == ["sh", "-c"]
                             for c in host.changes))

    def test_mismatched_portal_credential_is_recopied(self):
        host = FakeHost(
            lxd_installed=True, pool=True, bridge="10.77.0.1/24", profile=True,
            profile_devices={"root", "eth0"},
            containers={"orchestrator": {"ip": "10.77.0.20", "running": True},
                        "portal": {"ip": "10.77.0.10", "running": True}},
            credentials={"orchestrator": "d1", "portal": "stale"},
        )
        self.installer(host).run()
        self.assertEqual(host.credentials["portal"], "d1")
        self.assertFalse(any("civic_orchestrator.credentials" in c for c in host.changes))

    def test_existing_bridge_with_other_subnet_is_not_touched(self):
        host = FakeHost(lxd_installed=True, pool=True, bridge="10.99.0.1/24")
        with self.assertRaisesRegex(ni.InstallError, "civicbr0 exists"):
            self.installer(host).run()
        self.assertFalse(host.has(LXC, "network"))
        self.assertFalse(host.has(LXC, "init"))

    def test_existing_container_with_other_address_is_not_touched(self):
        host = FakeHost(
            lxd_installed=True, pool=True, bridge="10.77.0.1/24", profile=True,
            profile_devices={"root", "eth0"},
            containers={"orchestrator": {"ip": "10.77.0.99", "running": True}},
        )
        with self.assertRaisesRegex(ni.InstallError, "container orchestrator exists"):
            self.installer(host).run()
        self.assertFalse(host.has(LXC, "config", "device", "override"))

    def test_small_volume_group_falls_back_to_directory_pool(self):
        host = FakeHost(vg_free_gib=10)
        self.installer(host).run()
        self.assertTrue(host.has(LXC, "storage", "create", "civic", "dir"))
        self.assertFalse(host.has("lvcreate"))

    def test_non_lvm_root_falls_back_to_directory_pool(self):
        host = FakeHost(root_source="/dev/sda2", vg=None)
        self.installer(host).run()
        self.assertTrue(host.has(LXC, "storage", "create", "civic", "dir"))

    def test_explicit_lvm_without_lvm_root_stops(self):
        host = FakeHost(root_source="/dev/sda2", vg=None)
        with self.assertRaisesRegex(ni.InstallError, "requires the root filesystem on an LVM"):
            self.installer(host, storage="lvm").run()

    def test_requested_pool_size_is_respected_and_bounded(self):
        host = FakeHost()
        self.installer(host, pool_size_gib=300).run()
        self.assertTrue(host.has("lvcreate", "-y", "-L", "300G"))
        with self.assertRaisesRegex(ni.InstallError, "exceeds"):
            self.installer(FakeHost(vg_free_gib=100), pool_size_gib=300).run()

    def test_custom_subnet_moves_every_address(self):
        host = FakeHost()
        self.installer(host, subnet="10.88.5.0/24").run()
        self.assertTrue(host.has(LXC, "network", "create", "civicbr0", "ipv4.address=10.88.5.1/24"))
        self.assertTrue(host.has(LXC, "exec", "orchestrator", "--", "bash", ni.SETUP,
                                 "orchestrator", "10.88.5.20"))
        self.assertTrue(host.has(LXC, "exec", "portal", "--", "bash", ni.SETUP,
                                 "portal", "http://10.88.5.20:8045", "operator:root"))

    def test_installing_operator_is_recorded_on_the_portal(self):
        host = FakeHost()
        self.installer(host, operator="operator:sandor").run()
        self.assertTrue(host.has(LXC, "exec", "portal", "--", "bash", ni.SETUP,
                                 "portal", "http://10.77.0.20:8045", "operator:sandor"))

    def test_loopback_listener_fails_verification(self):
        host = FakeHost(loopback_answers=True)
        with self.assertRaisesRegex(ni.InstallError, "loopback"):
            self.installer(host).run()

    def test_civicmin_is_optional_and_pinned_when_given(self):
        host = FakeHost()
        inst = self.installer(host)
        inst.run()
        self.assertTrue(any("Civicmin was not installed" in n for n in inst.notes))
        self.assertFalse(any("kane-civicmin" in " ".join(c) for c in host.changes))

        host = FakeHost()
        self.installer(host, civicmin_repo="https://example.org/kane-civicmin",
                       civicmin_ref="v0.5.0").run()
        self.assertTrue(host.has(LXC, "exec", "portal", "--", "git", "clone", "--depth", "1",
                                 "--branch", "v0.5.0", "https://example.org/kane-civicmin",
                                 "/opt/kane-civicmin/v0.5.0"))
        self.assertTrue(host.has(LXC, "exec", "portal", "--", "bash",
                                 "/opt/kane-civicmin/v0.5.0/INSTALL/install.sh"))


class PreflightTests(unittest.TestCase):
    def test_only_supported_ubuntu(self):
        ni.check_os({"ID": "ubuntu", "VERSION_ID": "24.04"})
        for release in ({"ID": "debian", "VERSION_ID": "13"},
                        {"ID": "ubuntu", "VERSION_ID": "22.04"},
                        {"ID": "ubuntu", "VERSION_ID": "26.04"}):
            with self.assertRaises(ni.InstallError):
                ni.check_os(release)

    def test_os_release_parsing(self):
        parsed = ni.parse_os_release('NAME="Ubuntu"\nID=ubuntu\nVERSION_ID="24.04"\n# c\n')
        self.assertEqual(parsed["ID"], "ubuntu")
        self.assertEqual(parsed["VERSION_ID"], "24.04")

    def test_subnet_overlap_and_shape(self):
        net = ipaddress.IPv4Network("10.77.0.0/24")
        ni.check_subnet(net, [{"dst": "default", "dev": "enp9s0"},
                              {"dst": "10.0.0.0/24", "dev": "enp9s0"},
                              {"dst": "10.77.0.0/24", "dev": "civicbr0"}])
        with self.assertRaisesRegex(ni.InstallError, "overlaps"):
            ni.check_subnet(net, [{"dst": "10.77.0.0/16", "dev": "wg0"}])
        with self.assertRaisesRegex(ni.InstallError, "private"):
            ni.check_subnet(ipaddress.IPv4Network("8.8.8.0/24"), [])
        with self.assertRaisesRegex(ni.InstallError, "/27"):
            ni.check_subnet(ipaddress.IPv4Network("10.77.0.0/29"), [])

    def test_pool_size_planning(self):
        self.assertEqual(ni.plan_pool_size(363, None), 272)
        self.assertEqual(ni.plan_pool_size(363, 100), 100)
        with self.assertRaises(ni.InstallError):
            ni.plan_pool_size(50, 100)
        self.assertEqual(ni.gib_from_bytes(" 390572228608B "), 363)

    def test_source_tarball_contents(self):
        data = ni.source_tarball(ROOT)
        with tarfile.open(fileobj=io.BytesIO(data)) as tar:
            names = tar.getnames()
            members = tar.getmembers()
        self.assertIn("INSTALL/container/setup.sh", names)
        self.assertIn("src/civic_orchestrator/server.py", names)
        self.assertIn("INSTALL/requirements.lock", names)
        self.assertFalse(any(n.startswith(".git/") or n == ".git" for n in names))
        self.assertFalse(any("__pycache__" in n for n in names))
        self.assertTrue(all(m.uid == 0 and m.gid == 0 for m in members))
        self.assertFalse(any(m.mode & 0o7000 for m in members))


if __name__ == "__main__":
    unittest.main()
