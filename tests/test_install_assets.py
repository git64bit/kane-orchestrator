import re
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SYSTEMD = ROOT / "INSTALL" / "systemd"

# Literal addresses are deployment locators. Templates carry only loopback
# or installer placeholders, never a specific operator's network.
_IPV4_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")


class InstallAssetTests(unittest.TestCase):
    def read(self, name):
        return (SYSTEMD / name).read_text(encoding="utf-8")

    def test_templates_carry_no_operator_specific_addresses(self):
        for path in sorted(SYSTEMD.iterdir()):
            text = path.read_text(encoding="utf-8")
            for address in _IPV4_RE.findall(text):
                self.assertEqual(
                    address,
                    "127.0.0.1",
                    f"{path.name} contains a literal address: {address}",
                )

    def test_orchestrator_listens_on_bridge_placeholder_with_protected_credentials(self):
        unit = self.read("civic-orchestrator.service")
        self.assertIn("--listen @ORCHESTRATOR_LISTEN@", unit)
        self.assertIn("--publication-base-url @PUBLICATION_BASE_URL@", unit)
        self.assertIn(
            "--publication-budget-policy "
            "/etc/civic-orchestrator/publication-budget-v1.json",
            unit,
        )
        self.assertIn(
            "LoadCredential=adapter.json:"
            "/etc/civic-orchestrator/credentials/adapter.json",
            unit,
        )
        self.assertIn(
            "LoadCredential=publication-service.json:"
            "/etc/civic-orchestrator/credentials/publication-service.json",
            unit,
        )
        self.assertIn("--adapter-credential-name adapter.json", unit)
        self.assertIn(
            "--publication-credential-name publication-service.json",
            unit,
        )

    def test_broker_socket_is_the_shared_civicmin_boundary(self):
        socket_unit = self.read("civic-custom-command-broker.socket")
        self.assertIn(
            "ListenStream=/run/civic-orchestrator/custom-command.sock",
            socket_unit,
        )
        self.assertIn("SocketGroup=civic-participants", socket_unit)
        self.assertIn("SocketMode=0660", socket_unit)

    def test_broker_service_is_local_only_and_holds_no_credentials(self):
        unit = self.read("civic-custom-command-broker.service")
        self.assertIn("RestrictAddressFamilies=AF_UNIX", unit)
        self.assertNotIn("AF_INET", unit)
        self.assertIn("-m civic_orchestrator.custom_command_broker", unit)
        self.assertIn(
            "--access-policy "
            "/etc/civic-orchestrator/custom-command-access-v1.yaml",
            unit,
        )
        self.assertIn(
            "--access-schema "
            "/etc/civic-orchestrator/custom-command-access-v1.schema.json",
            unit,
        )
        self.assertNotIn("--orchestrator-base-url", unit)
        self.assertNotIn("LoadCredential=", unit)

    def test_publication_service_requires_credential_and_placeholder_listen(self):
        unit = self.read("civic-publication.service")
        self.assertIn("--listen @PUBLICATION_LISTEN@", unit)
        self.assertIn("--port 8046", unit)
        self.assertIn(
            "LoadCredential=publication-service.json:"
            "/etc/civic-publication/credentials/publication-service.json",
            unit,
        )
        self.assertIn("--credential-name publication-service.json", unit)


if __name__ == "__main__":
    unittest.main()
