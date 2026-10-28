#!/usr/bin/env python3
"""Build and scan the pinned CSI repair locally; never publish or deploy."""

import argparse
import hashlib
import json
import os
from pathlib import Path
import platform
import shutil
import subprocess
import tarfile
import urllib.request

ROOT = Path(__file__).resolve().parent


def digest(path):
    with path.open('rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()


def download(item, destination):
    destination.parent.mkdir(parents=True, exist_ok=True)
    if not destination.exists():
        with urllib.request.urlopen(item['url'], timeout=120) as response:
            with destination.open('wb') as output:
                shutil.copyfileobj(response, output)
    if digest(destination) != item['sha256']:
        raise ValueError('Input checksum mismatch: ' + destination.name)


def extract(archive, destination, strip_root=False):
    with tarfile.open(archive) as source:
        for member in source.getmembers():
            if strip_root:
                parts = member.name.split('/', 1)
                if len(parts) != 2 or not parts[1]:
                    continue
                member.name = parts[1]
            source.extract(member, destination, filter='data')


def run(argv, log, **kwargs):
    with log.open('w') as output:
        subprocess.run(argv, stdout=output, stderr=subprocess.STDOUT, check=True, **kwargs)


def validate_scan(scan, image_id, binary, blocked_severities):
    if scan.get('Metadata', {}).get('ImageID') != image_id:
        raise ValueError('Scan subject differs from the built image')
    binaries = [r for r in scan.get('Results', [])
                if r.get('Type') == 'gobinary' and r.get('Target') == binary]
    if len(binaries) != 1 or not binaries[0].get('Packages'):
        raise ValueError('Expected binary inventory is missing from scan')
    findings = [v for result in scan['Results'] for v in result.get('Vulnerabilities', [])]
    if any(v['Severity'] in blocked_severities for v in findings):
        raise ValueError('Image scan failed the referenced critical-vulnerability policy')
    if any(v['PkgName'] in {'stdlib', 'golang.org/x/net'} for v in findings):
        raise ValueError('Patched Go dependency still has reported vulnerabilities')
    return findings


def archive_config_digest(archive, tag):
    with tarfile.open(archive) as source:
        manifests = json.load(source.extractfile('manifest.json'))
        if len(manifests) != 1 or tag not in manifests[0].get('RepoTags', []):
            raise ValueError('Archive contains an unexpected image inventory')
        config = source.extractfile(manifests[0]['Config']).read()
        metadata = json.loads(config)
        if metadata.get('os') != 'linux' or metadata.get('architecture') != 'amd64':
            raise ValueError('Archive platform differs from selected Linux/amd64')
        return 'sha256:' + hashlib.sha256(config).hexdigest()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--component', required=True, choices=['nfs', 'registrar', 'liveness'])
    parser.add_argument('--work-dir', type=Path, required=True)
    parser.add_argument('--tag', required=True)
    parser.add_argument('--trivy', required=True)
    args = parser.parse_args()
    lock = json.loads((ROOT / 'build-lock.json').read_text())
    policy_path = ROOT / 'image-policy.json'
    if digest(policy_path) != lock['policy_snapshot']['sha256']:
        raise ValueError('Pinned APP policy projection differs')
    policy = json.loads(policy_path.read_text())['evidence']
    if policy['scanner'] != 'trivy':
        raise ValueError('Unsupported scanner in pinned APP policy')
    item = lock['components'][args.component]
    work = args.work_dir.resolve()
    work.mkdir(parents=True, exist_ok=False)
    host = platform.system().lower() + '/' + {'aarch64': 'arm64', 'x86_64': 'amd64'}.get(
        platform.machine(), platform.machine())
    compiler = lock['go']['archives'][host]
    download(compiler, work / 'go.tar.gz')
    extract(work / 'go.tar.gz', work)
    download(item['source'], work / 'source.tar.gz')
    source = work / 'source'
    source.mkdir()
    extract(work / 'source.tar.gz', source, strip_root=True)
    for name in ['go.mod', 'go.sum']:
        replacement = ROOT / (args.component + '-' + name)
        if digest(replacement) != item['locks'][name]:
            raise ValueError('Modified dependency lock: ' + name)
        shutil.copyfile(replacement, source / name)
    env = {**os.environ, 'GOTOOLCHAIN': 'local', 'GOPATH': str(work / 'gopath'),
           'GOCACHE': str(work / 'gocache'), 'GOMAXPROCS': '4',
           'GOFLAGS': '-mod=readonly', 'CGO_ENABLED': '0',
           'GOPROXY': 'https://proxy.golang.org', 'GOSUMDB': 'sum.golang.org',
           'GOPRIVATE': '', 'GONOSUMDB': '', 'GONOPROXY': ''}
    go = str(work / 'go/bin/go')
    run([go, 'mod', 'download'], work / 'download.log', cwd=source, env=env)
    run([go, 'mod', 'verify'], work / 'module-verify.log', cwd=source, env=env)
    tests = ['./cmd/...'] + (['./pkg/...'] if (source / 'pkg').is_dir() else [])
    if platform.system() == 'Linux':
        run([go, 'test', '-p', '2', '-short', *tests], work / 'tests.log', cwd=source, env=env)
    else:
        packages = subprocess.check_output([go, 'list', *tests], cwd=source, env=env, text=True).splitlines()
        for index, package in enumerate(packages):
            test = work / ('unit-' + str(index))
            run([go, 'test', '-c', '-p', '2', '-o', str(test), package],
                work / ('test-compile-' + str(index) + '.log'), cwd=source,
                env={**env, 'GOOS': 'linux', 'GOARCH': 'amd64'})
            if test.exists():
                relative = package.removeprefix('github.com/kubernetes-csi/' +
                                               item['source']['repository'].rsplit('/', 1)[-1] + '/')
                run(['docker', 'run', '--rm', '--platform', 'linux/amd64', '--network=none',
                     '--cap-drop=ALL', '--mount', 'type=bind,src=' + str(work) + ',dst=/work',
                     '--workdir', '/work/source/' + relative, lock['nfs_runtime']['base'],
                     '/work/' + test.name, '-test.short', '-test.v'],
                    work / ('tests-' + str(index) + '.log'))
    run([go, 'mod', 'vendor'], work / 'vendor.log', cwd=source, env=env)
    context = work / 'context'
    context.mkdir()
    binary = context / item['binary']
    run([go, 'build', '-mod=vendor', '-p', '2', '-trimpath', '-buildvcs=false',
         '-ldflags', item['ldflags'], '-o', str(binary), './cmd/' + item['binary']],
        work / 'compile.log', cwd=source, env={**env, 'GOOS': 'linux', 'GOARCH': 'amd64'})
    run([go, 'version', '-m', str(binary)], work / 'binary-modules.txt', env=env)
    licenses = context / 'licenses'
    licenses.mkdir()
    for path in source.rglob('*'):
        if path.is_file() and path.name.upper().startswith(('LICENSE', 'COPYING', 'NOTICE')):
            target = licenses / path.relative_to(source)
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(path, target)
    shutil.copyfile(ROOT / (args.component + '.Dockerfile'), context / 'Dockerfile')
    if args.component == 'nfs':
        for package in lock['nfs_runtime']['packages']:
            download(package, context / 'debs' / package['filename'])
    package_image(args, work, lock, item, policy)


def package_image(args, work, lock, item, policy):
    context = work / 'context'
    binary = context / item['binary']
    run(['docker', 'build', '--platform', 'linux/amd64', '--network=none', '--provenance=false',
         '--tag', args.tag, str(context)], work / 'image-build.log')
    run(['docker', 'run', '--rm', '--platform', 'linux/amd64', '--network=none',
         '--read-only', '--cap-drop=ALL', args.tag, '--help'], work / 'cli.log')
    if args.component == 'nfs':
        run(['docker', 'run', '--rm', '--platform', 'linux/amd64', '--network=none',
             '--read-only', '--cap-drop=ALL', '--entrypoint', '/sbin/mount.nfs', args.tag, '-V'],
            work / 'mount-helper.log')
    archive = work / 'image.tar'
    subprocess.run(['docker', 'save', '--output', str(archive), args.tag], check=True)
    config_digest = archive_config_digest(archive, args.tag)
    common = [args.trivy, 'image', '--quiet', '--input', str(archive), '--platform',
              'linux/amd64', '--scanners', 'vuln', '--timeout', '10m']
    subprocess.run([*common, '--format', 'json', '--output', str(work / 'scan.json')], check=True)
    subprocess.run([*common, '--format', 'spdx-json', '--output', str(work / 'sbom.spdx.json')], check=True)
    scan = json.loads((work / 'scan.json').read_text())
    # Spec: REL-GATE-001 — failed scans cannot authorize image publication or runtime admission.
    image_id = subprocess.check_output(['docker', 'image', 'inspect', args.tag,
                                        '--format', '{{.Id}}'], text=True).strip()
    findings = validate_scan(scan, config_digest, item['binary'], policy['blocked_severities'])
    result = {'component': args.component, 'tag': args.tag, 'image_id': image_id,
              'platform': 'linux/amd64', 'config_digest': config_digest, 'source': item['source'],
              'build_lock_sha256': digest(ROOT / 'build-lock.json'),
              'binary_sha256': digest(binary), 'archive_sha256': digest(archive),
              'scan_sha256': digest(work / 'scan.json'),
              'sbom_sha256': digest(work / 'sbom.spdx.json'),
              'findings': len(findings), 'published': False,
              'provenance': 'Local build record only; no trusted-hosted attestation or deployment authority'}
    (work / 'result.json').write_text(json.dumps(result, indent=2) + '\n')
    print(json.dumps(result, indent=2))


if __name__ == '__main__':
    main()
