import argparse
import gzip
import hashlib
import json
import os
import shutil
import tarfile
from pathlib import Path
from typing import Optional, Dict, Any

import requests
from tqdm import tqdm

REGISTRY_USERNAME = "REGISTRY_USERNAME"
REGISTRY_PASSWORD = "REGISTRY_PASSWORD"

EMPTY_LAYER_JSON = '{"created":"1970-01-01T00:00:00Z","container_config":{"Hostname":"","Domainname":"","User":"",' \
                   '"AttachStdin":false,"AttachStdout":false,"AttachStderr":false,"Tty":false,"OpenStdin":false, ' \
                   '"StdinOnce":false,"Env":null,"Cmd":null,"Image":"", "Volumes":null,"WorkingDir":"",' \
                   '"Entrypoint":null,"OnBuild":null,"Labels":null}}'


def print_error_response(resp):
    print(f"Status code {resp.status_code}")
    print(f"Headers: {resp.headers}")
    print(f"Body: {resp.text}")


class ImageReference:
    def __init__(self, image_reference: str, allow_insecure: bool = False, use_http: bool = False):
        self._allow_insecure = allow_insecure
        self._use_http = use_http

        repository = ""
        tag = None
        digest = None

        parts = image_reference.split("/")

        registry = parts[0]
        if len(parts) > 2:
            repository = "/".join(parts[1:-1]) + "/"

        try:
            image, digest = parts[-1].split("@")
            tag = None
        except ValueError:
            try:
                image, tag = parts[-1].split(":")
            except ValueError:
                image = parts[-1]

        self._registry = registry
        self._image = repository + image
        self._tag = tag
        self._digest = digest

        # Disable warnings if allow_insecure
        if allow_insecure:
            import urllib3
            urllib3.disable_warnings()

    @property
    def registry(self) -> str:
        return self._registry

    @property
    def image(self) -> str:
        return self._image

    @property
    def prefixed_tag_or_digest(self) -> str:
        if self._tag is None and self._digest is None:
            raise ValueError("Either tag or digest must be supplied")
        if self._tag:
            return f":{self._tag}"
        return f"@{self._digest}"

    @property
    def tag_or_digest(self) -> str:
        if self._tag is None and self._digest is None:
            raise ValueError("Either tag or digest must be supplied")
        if self._tag:
            return self._tag
        return self._digest

    @property
    def scheme(self) -> str:
        # If we allow insecure try http first
        if self._use_http:
            return "http://"
        return "https://"

    @property
    def allow_insecure(self) -> bool:
        return self._allow_insecure

    def __repr__(self) -> str:
        return f"{self.registry}/{self.image}{self.prefixed_tag_or_digest}"


class Auth:
    def __init__(self, image_reference: ImageReference, username: Optional[str] = None, password: Optional[str] = None):
        self._auth_url = None
        self._auth_service = ""

        self._image_reference = image_reference
        self._username = os.environ.get(REGISTRY_USERNAME)
        if username is not None:
            self._username = username

        self._password = os.environ.get(REGISTRY_PASSWORD)
        if password is not None:
            self._password = password

        self._authentication_endpoint()

    def _authentication_endpoint(self) -> None:
        resp = requests.get(f"{self._image_reference.scheme}{self._image_reference.registry}/v2/",
                            verify=not self._image_reference.allow_insecure)

        if resp.status_code == 401:
            www_authenticate = resp.headers["www-authenticate"].split(",")
            for h in www_authenticate:
                www_auth = h.split("=")
                if 'Bearer realm' == www_auth[0]:
                    self._auth_url = www_auth[1].replace('"', '')
                if 'service' in www_auth[0]:
                    self._auth_service = www_auth[1].replace('"', '')

    def authentication_header(self) -> Dict[str, str]:
        if self._auth_url is None:
            return {}

        auth = None
        if self._username is not None and self._password is not None:
            auth = (self._username, self._password)

        resp = requests.get(f"{self._auth_url}?"
                            f"service={self._auth_service}&scope=repository:{self._image_reference.image}:pull",
                            auth=auth,
                            verify=not self._image_reference.allow_insecure)

        if resp.status_code != 200:
            print_error_response(resp)
            exit(1)

        access_token = resp.json()['token']
        auth_head = {'Authorization': 'Bearer ' + access_token}
        return auth_head


class ListCommand:
    def __init__(self, image_ref: ImageReference, auth: Auth):
        self._image_ref = image_ref
        self._auth = auth

    def invoke(self) -> None:
        resp = requests.get(
            f"{self._image_ref.scheme}{self._image_ref.registry}/v2/{self._image_ref.image}/tags/list",
            headers=self._auth.authentication_header(),
            verify=not self._image_ref.allow_insecure)
        if resp.status_code == 200:
            print(f"Available tags: {resp.json()['tags']}")
        else:
            print_error_response(resp)
            exit(1)


class SaveCommand:
    def __init__(self, image_ref: ImageReference, auth: Auth):
        self._image_ref = image_ref
        self._auth = auth
        self._staging_dir = Path(
            f"./tmp_{image_ref.image.replace('/', '_')}_{image_ref.prefixed_tag_or_digest.replace(':', '@')}")
        self._output_tar = Path(
            f"./{image_ref.image.replace('/', '_')}_{image_ref.tag_or_digest.replace(':', '@')}.tar")
        self._target_image_tag = image_ref.tag_or_digest.replace(":", "_")  # Deal with the fact this might be a digest
        self._target_content: Dict[str, Any] = {
            'Config': "",
            'RepoTags': [],
            'Layers': []
        }

    def invoke(self) -> None:
        self._fetch_and_process_manifest()
        print(f"Creating image structure in: {self._staging_dir}")
        self._staging_dir.mkdir(parents=True, exist_ok=True)
        self._stage_root_json()
        self._stage_layer_folders()
        self._stage_manifest()
        self._stage_repositories()
        self._create_tar()

    def _fetch_and_process_manifest(self) -> None:
        headers = self._auth.authentication_header()
        headers['Accept'] = "application/vnd.docker.distribution.manifest.v2+json"

        ir = self._image_ref
        resp = requests.get(
            f"{ir.scheme}{ir.registry}/v2/{ir.image}/manifests/{ir.tag_or_digest}",
            headers=headers,
            verify=not ir.allow_insecure)

        if resp.status_code != 200:
            print_error_response(resp)
            exit(1)

        self._source_layers = resp.json()['layers']
        self._source_digest = resp.json()['config']['digest']

    def _stage_root_json(self) -> None:
        digest = self._source_digest
        ir = self._image_ref
        digest_resp = requests.get(
            f"{ir.scheme}{ir.registry}/v2/{ir.image}/blobs/{digest}",
            headers=self._auth.authentication_header(),
            verify=not ir.allow_insecure)
        self._root_config = digest_resp.content

        with (self._staging_dir / f"{digest[7:]}.json").open("wb") as f:
            f.write(self._root_config)

        self._target_content['Config'] = f"{digest[7:]}.json"
        self._target_content['RepoTags'] = [f"{self._image_ref.image}:{self._target_image_tag}"]

    def _stage_layer_folders(self) -> None:
        parent_id = ""
        for layer in self._source_layers:
            parent_id = self._stage_layer_folder(parent_id, layer)

    def _stage_layer_folder(self, parent_id: str, layer: Dict[str, Any]) -> str:
        ir = self._image_ref

        digest = layer['digest']
        generated_layer_id = hashlib.sha256((parent_id + '\n' + digest).encode('utf-8')).hexdigest()
        layer_dir = self._staging_dir / generated_layer_id
        layer_dir.mkdir(exist_ok=True)

        with (layer_dir / "VERSION").open("w") as f:
            f.write("1.0")

        headers = self._auth.authentication_header()
        headers['Accept'] = "application/vnd.docker.distribution.manifest.v2+json"
        resp = requests.get(
            f"{ir.scheme}{ir.registry}/v2/{ir.image}/blobs/{digest}",
            headers=headers,
            stream=True,
            verify=not ir.allow_insecure)

        if resp.status_code != 200:
            print_error_response(resp)
            exit(1)

        content_length = int(resp.headers["Content-Length"])
        print(f"Downloading {digest}")
        with tqdm(total=content_length, unit="B", unit_scale=True) as pbar:
            with (layer_dir / "layer.tar.gz").open("wb") as tar_gz:
                for chunk in resp.iter_content(chunk_size=8192):
                    if not chunk:
                        # We are done...
                        continue
                    tar_gz.write(chunk)
                    pbar.update(len(chunk))

        print(f"Extracting {digest}")
        with gzip.open(layer_dir / "layer.tar.gz", "rb") as tar_gz, (layer_dir / "layer.tar").open("wb") as tar:
            shutil.copyfileobj(tar_gz, tar)
        (layer_dir / "layer.tar.gz").unlink()
        self._target_content["Layers"].append(f"{generated_layer_id}/layer.tar")

        if self._source_layers[-1]["digest"] == digest:
            # Final layer is config manifest without history and rootfs
            json_obj = json.loads(self._root_config)
            del json_obj['history']
            del json_obj['rootfs']
        else:
            json_obj = json.loads(EMPTY_LAYER_JSON)

        json_obj['id'] = generated_layer_id
        if parent_id:
            json_obj['parent'] = parent_id

        with (layer_dir / "json").open("w") as f:
            f.write(json.dumps(json_obj))

        return generated_layer_id

    def _stage_manifest(self) -> None:
        with(self._staging_dir / "manifest.json").open("w") as f:
            f.write(json.dumps([self._target_content]))

    def _stage_repositories(self) -> None:
        json_obj = {
            f"{self._image_ref.registry}/{self._image_ref.image}": {
                self._target_image_tag: self._target_content["Layers"][-1].replace("/layer.tar", "")
            }
        }
        with(self._staging_dir / "repositories").open("w") as f:
            f.write(json.dumps(json_obj))

    def _create_tar(self) -> None:
        print(f"Creating archive {self._output_tar}")
        with tarfile.open(self._output_tar, "w") as tar:
            tar.add(self._staging_dir, arcname=os.path.sep)
        shutil.rmtree(self._staging_dir)


def run() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--username",
                        help="Repository username, will use REGISTRY_USERNAME from environment if not supplied",
                        default=None)
    parser.add_argument("--password",
                        help="Repository password, will use REGISTRY_PASSWORD from environment if not supplied",
                        default=None)
    parser.add_argument("--use-http",
                        action="store_true",
                        help="Will use HTTP access to the registry",
                        default=False)
    parser.add_argument("--allow-insecure",
                        action="store_true",
                        help="Will ignore any certificate errors when using HTTPS to talk to the registry",
                        default=False)

    subparsers = parser.add_subparsers(dest="command")

    parser_list = subparsers.add_parser("list")
    parser_list.add_argument("image_reference", help="registry/[repository/]image[:tag|@digest]")

    parser_save = subparsers.add_parser("save")
    parser_save.add_argument("image_reference", help="registry/[repository/]image[:tag|@digest]")

    args = parser.parse_args()

    if args.command == 'list':
        image_ref = ImageReference(args.image_reference, allow_insecure=args.allow_insecure, use_http=args.use_http)
        auth = Auth(image_ref, username=args.username, password=args.password)
        ListCommand(image_ref, auth).invoke()
    elif args.command == 'save':
        image_ref = ImageReference(args.image_reference, allow_insecure=args.allow_insecure, use_http=args.use_http)
        auth = Auth(image_ref, username=args.username, password=args.password)
        SaveCommand(image_ref, auth).invoke()


if __name__ == "__main__":
    run()
