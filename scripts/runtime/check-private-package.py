#!/usr/bin/env python3
"""Fail closed unless a seeded registry package exists and denies anonymous pull."""
import argparse
import json
import subprocess
from urllib.error import HTTPError
from urllib.parse import quote, urlencode
from urllib.request import Request, urlopen


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--owner', required=True)
    args = parser.parse_args()
    repo = args.owner.lower()+'/atrust-native'
    # This harmless seed tag must exist. Docker must already be authenticated.
    subprocess.run(['docker','manifest','inspect','ghcr.io/'+repo+':package-init'],
                   check=True, stdout=subprocess.DEVNULL, timeout=30)
    params = urlencode({'service':'ghcr.io','scope':'repository:'+repo+':pull'})
    try:
        with urlopen('https://ghcr.io/token?'+params, timeout=15) as response:
            token = json.load(response)['token']
        request = Request('https://ghcr.io/v2/'+quote(repo,safe='/')+'/manifests/package-init',
                          headers={'Authorization':'Bearer '+token,
                                   'Accept':'application/vnd.docker.distribution.manifest.v2+json, application/vnd.oci.image.manifest.v1+json'})
        with urlopen(request, timeout=15):
            pass
    except HTTPError as exc:
        if exc.code in (401,403,404):
            print('Authenticated seed exists; anonymous pull denied: private publication gate PASS')
            return
        raise
    raise RuntimeError('Refusing to publish: package is anonymously readable')


if __name__ == '__main__':
    main()
