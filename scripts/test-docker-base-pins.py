#!/usr/bin/env python3
import importlib.util
import json
import shutil
import tempfile
import unittest
from pathlib import Path


SCRIPT = Path(__file__).with_name("check-docker-base-pins.py")
SPEC = importlib.util.spec_from_file_location("check_docker_base_pins", SCRIPT)
CHECKER = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(CHECKER)


class DockerBasePinTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.repo = Path(self.temporary.name)
        for relative in (
            "Dockerfile.engine",
            "go-envelope/Dockerfile",
            "config/release-channels/base-images-v1.json",
        ):
            source = SCRIPT.parent.parent / relative
            target = self.repo / relative
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(source, target)
        CHECKER.REPO = self.repo
        CHECKER.INVENTORY = (
            self.repo / "config/release-channels/base-images-v1.json"
        )

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def assert_rejected(self, expected: str, action) -> None:
        with self.assertRaisesRegex(SystemExit, expected):
            action()

    def test_reviewed_inventory_matches_every_dockerfile(self) -> None:
        data = CHECKER.load_inventory()
        self.assertEqual(len(CHECKER.verify_local(data)), 4)

    def test_new_dockerfile_must_be_inventoried(self) -> None:
        (self.repo / "nested").mkdir()
        (self.repo / "nested/Dockerfile").write_text("FROM alpine:latest\n")
        data = CHECKER.load_inventory()
        self.assert_rejected("Dockerfile inventory drift", lambda: CHECKER.verify_local(data))

    def test_digestless_from_is_rejected(self) -> None:
        dockerfile = self.repo / "go-envelope/Dockerfile"
        dockerfile.write_text(
            dockerfile.read_text().replace(
                "golang:1.26.5-alpine3.24@sha256:0178a641fbb4858c5f1b48e34bdaabe0350a330a1b1149aabd498d0699ff5fb2",
                "golang:1.26.5-alpine3.24",
            )
        )
        data = CHECKER.load_inventory()
        self.assert_rejected("base-image pin drift", lambda: CHECKER.verify_local(data))

    def test_mutable_inventory_tag_is_rejected(self) -> None:
        data = json.loads(CHECKER.INVENTORY.read_text())
        data["images"][0]["tag"] = "latest"
        CHECKER.INVENTORY.write_text(json.dumps(data))
        data = CHECKER.load_inventory()
        self.assert_rejected("mutable or empty tag", lambda: CHECKER.verify_local(data))


if __name__ == "__main__":
    unittest.main()
