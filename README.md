### Docker Registry Helper

A utility script to help with extracting images from a registry, inspired by 
[docker-drag](https://github.com/NotGlop/docker-drag).

### Virtual environment setup

```shell
python -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

### Usage

```shell
python3 registry_helper.py -h
usage: registry_helper.py [-h] [--username USERNAME] [--password PASSWORD] [--allow-insecure] {list,save} ...

positional arguments:
  {list,save}

optional arguments:
  -h, --help           show this help message and exit
  --username USERNAME  Repository username, will use REGISTRY_USERNAME from environment if not supplied
  --password PASSWORD  Repository password, will use REGISTRY_PASSWORD from environment if not supplied
  --allow-insecure     Will try HTTP access to the registry before HTTPS and ignore certificate errors
```

#### List available tags
```shell
python3 registry_helper.py list registry-1.docker.io/library/hello-world
```

#### Save using a tag
```shell
python3 docker_pull.py save registry-1.docker.io/library/ubuntu:18.04
```

#### Save using a digest
```shell
python3 docker_pull.py save registry-1.docker.io/library/ubuntu@sha256:fb5104deb0ffa22606091c5fc569d7c013e826a58cf9c3d0dedcb7e99ac21cd3
```
