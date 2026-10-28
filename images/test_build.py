"""Refuse mismatched image scans and unsafe or corrupted build inputs."""

import copy
import importlib.util
import io
import hashlib
import json
from pathlib import Path
import tarfile
import tempfile
import unittest

ROOT = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location('csi_build', ROOT / 'build.py')
build = importlib.util.module_from_spec(spec)
spec.loader.exec_module(build)


class BuildInputTests(unittest.TestCase):
    def test_scan_identity_comes_from_archive_config_and_checks_platform_and_tag(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            for architecture in ['amd64', 'arm64']:
                config = json.dumps({'os': 'linux', 'architecture': architecture}).encode()
                manifest = json.dumps([{'Config': 'config.json', 'RepoTags': ['selected:tag']}]).encode()
                archive = root / (architecture + '.tar')
                with tarfile.open(archive, 'w') as output:
                    for name, body in [('manifest.json', manifest), ('config.json', config)]:
                        member = tarfile.TarInfo(name)
                        member.size = len(body)
                        output.addfile(member, io.BytesIO(body))
                if architecture == 'amd64':
                    self.assertEqual(build.archive_config_digest(archive, 'selected:tag'),
                                     'sha256:' + hashlib.sha256(config).hexdigest())
                else:
                    with self.assertRaises(ValueError):
                        build.archive_config_digest(archive, 'selected:tag')
                with self.assertRaises(ValueError):
                    build.archive_config_digest(archive, 'another:tag')

    def test_scan_requires_the_exact_image_and_complete_binary_inventory(self):
        scan = {'Metadata': {'ImageID': 'sha256:expected'}, 'Results': [
            {'Type': 'gobinary', 'Target': 'driver', 'Packages': [{'Name': 'stdlib'}]}]}
        self.assertEqual(build.validate_scan(scan, 'sha256:expected', 'driver', ['CRITICAL']), [])
        for mutate in [lambda s: s['Metadata'].update(ImageID='sha256:another'),
                       lambda s: s.update(Results=[]),
                       lambda s: s['Results'][0].update(Packages=[]),
                       lambda s: s['Results'][0].update(Target='different'),
                       lambda s: s['Results'].append(copy.deepcopy(s['Results'][0]))]:
            candidate = copy.deepcopy(scan)
            mutate(candidate)
            with self.assertRaises(ValueError):
                build.validate_scan(candidate, 'sha256:expected', 'driver', ['CRITICAL'])

    def test_policy_failure_and_unfixed_go_dependencies_refuse_publication(self):
        for package, severity, blocked in [('zlib', 'CRITICAL', ['CRITICAL']),
                                           ('zlib', 'HIGH', ['HIGH']),
                                           ('stdlib', 'LOW', ['CRITICAL']),
                                           ('golang.org/x/net', 'MEDIUM', ['CRITICAL'])]:
            scan = {'Metadata': {'ImageID': 'sha256:expected'}, 'Results': [
                {'Type': 'gobinary', 'Target': 'driver', 'Packages': [{'Name': 'stdlib'}],
                 'Vulnerabilities': [{'PkgName': package, 'Severity': severity}]}]}
            with self.subTest(package=package, severity=severity), self.assertRaises(ValueError):
                build.validate_scan(scan, 'sha256:expected', 'driver', blocked)

    def test_cached_download_is_rehashed_before_use(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'input'
            path.write_bytes(b'changed')
            with self.assertRaises(ValueError):
                build.download({'url': 'https://invalid.example/never-called', 'sha256': '0' * 64}, path)

    def test_source_archive_cannot_escape_the_workspace(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            archive = root / 'input.tar'
            with tarfile.open(archive, 'w') as output:
                member = tarfile.TarInfo('source/../../escape')
                member.size = 1
                output.addfile(member, io.BytesIO(b'x'))
            with self.assertRaises(tarfile.FilterError):
                build.extract(archive, root / 'source', strip_root=True)
            self.assertFalse((root / 'escape').exists())


if __name__ == '__main__':
    unittest.main()
