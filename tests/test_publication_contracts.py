import base64
import hashlib
import json
import tempfile
import unittest

import yaml
from pathlib import Path

from civic_orchestrator.runtime import ContractStore


ROOT = Path(__file__).resolve().parents[1]


class PublicationContractTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.contracts = ContractStore(ROOT)

    def artifact(self, payload=b"civic publication\n"):
        return {
            "media_type": "text/plain",
            "size_bytes": len(payload),
            "sha256": hashlib.sha256(payload).hexdigest(),
            "encoding": "base64",
            "content": base64.b64encode(payload).decode("ascii"),
        }

    def test_publication_input_validates(self):
        value = {
            "artifact": self.artifact(),
        }
        self.contracts.validate(
            "publication-publish-input-v1.schema.json",
            value,
        )

    def test_publication_label_is_rejected(self):
        value = {
            "artifact": self.artifact(),
            "label": "descriptive scope is not accepted at publication time",
        }
        with self.assertRaises(Exception):
            self.contracts.validate(
                "publication-publish-input-v1.schema.json",
                value,
            )

    def test_publication_service_request_validates(self):
        value = {
            "contract_version": 1,
            "workflow_id": "wf:test-publication",
            "operation": "publication.publish",
            "artifact": self.artifact(),
        }
        self.contracts.validate(
            "publication-service-request-v1.schema.json",
            value,
        )

    def test_publication_service_success_validates(self):
        value = {
            "contract_version": 1,
            "workflow_id": "wf:test-publication",
            "operation": "publication.publish",
            "sha256": "0" * 64,
            "size_bytes": 0,
            "cid": "bafkreibqfrpsjusanrs6tthjrxvgutdlldbwtjr5zer2uvzfkfj3xsnh5e",
            "cid_profile": "civic-ipfs-kubo-v1",
            "pinned": True,
            "verified": True,
        }
        self.contracts.validate(
            "publication-service-result-v1.schema.json",
            value,
        )

    def test_publication_service_failure_validates(self):
        value = {
            "contract_version": 1,
            "workflow_id": "wf:test-publication",
            "operation": "publication.publish",
            "failure_class": "integrity-mismatch",
            "message": "decoded bytes do not match declared digest",
            "retryable": False,
        }
        self.contracts.validate(
            "publication-service-failure-v1.schema.json",
            value,
        )

    def test_invalid_base64_shape_is_rejected(self):
        value = {"artifact": self.artifact()}
        value["artifact"]["content"] = "***not-base64***"
        with self.assertRaises(Exception):
            self.contracts.validate(
                "publication-publish-input-v1.schema.json",
                value,
            )

    def test_oversize_artifact_is_rejected(self):
        value = {"artifact": self.artifact()}
        value["artifact"]["size_bytes"] = 262145
        with self.assertRaises(Exception):
            self.contracts.validate(
                "publication-publish-input-v1.schema.json",
                value,
            )

    def test_publication_workflow_definition_validates(self):
        value = yaml.safe_load(
            (ROOT / "workflows" / "publication-publish-v1.yaml").read_text(
                encoding="utf-8"
            )
        )
        self.contracts.validate(
            "publication-workflow-definition-v1.schema.json",
            value,
        )
        self.assertEqual(value["operation"], "publication.publish")
        self.assertEqual(
            value["authorization_policy"],
            "publication-policy-v1",
        )

    def test_catalog_contains_publication_contracts(self):
        catalog = json.loads(
            (ROOT / "schemas" / "catalog-v1.json").read_text(encoding="utf-8")
        )
        ids = {item["id"] for item in catalog["schemas"]}
        for required in {
            "urn:civic-orchestrator:schema:publication-artifact:v1",
            "urn:civic-orchestrator:schema:publication-publish-input:v1",
            "urn:civic-orchestrator:schema:publication-service-request:v1",
            "urn:civic-orchestrator:schema:publication-service-result:v1",
            "urn:civic-orchestrator:schema:publication-service-failure:v1",
            "urn:civic-orchestrator:schema:publication-workflow-definition:v1",
        }:
            self.assertIn(required, ids)


if __name__ == "__main__":
    unittest.main()
