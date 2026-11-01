# Object storage: RustFS and the `s3` configuration section

!!! info ""

    * **Deprecated in**: `OpenCTI 7.26XXXX.0` (the `minio` configuration section)
    * **Changed in**: `OpenCTI 7.26XXXX.0` (the reference Docker deployment runs RustFS: its storage volume must be moved)

## Description of changes

- Starting with OpenCTI 7.26XXXX.0, the reference Docker deployment ([OpenCTI-Platform/docker](https://github.com/OpenCTI-Platform/docker)), the development stack and the CI run [RustFS](https://rustfs.com) as S3 object storage. RustFS is an open source (Apache 2.0) S3-compatible server. It replaces [Silo](https://github.com/pgsty/silo), the MinIO fork used since the [MinIO repository](https://github.com/minio/minio) was archived in April 2026.
- OpenCTI works with any S3-compatible service (AWS S3, cloud object storage, RustFS, Silo, MinIO...). Nothing in the platform depends on RustFS.
- The configuration section `minio` is renamed `s3`: `minio:endpoint` becomes `s3:endpoint`, `MINIO__ENDPOINT` becomes `S3__ENDPOINT`, and so on for every parameter of the section. The former names are still read: an existing configuration keeps working, and a warning listing the former names in use (or ignored because the new name is set) is logged at startup.

## Configuration

Nothing is mandatory. When you can, rename the parameters:

| Former name                       | New name                       |
|:----------------------------------|:-------------------------------|
| `minio:<parameter>`               | `s3:<parameter>`               |
| `MINIO__<PARAMETER>`              | `S3__<PARAMETER>`              |
| `MINIO__CREDENTIALS_PROVIDER__*`  | `S3__CREDENTIALS_PROVIDER__*`  |

For each parameter, the former name is used only when the new name is not set at the same or a higher priority level (environment variables first, then command line arguments, then the configuration file, then the default values). A parameter set to an empty value counts as set. Do not keep both names with different values.

Versions before OpenCTI 7.26XXXX.0 only read the former names: keep them as long as you may need to go back to such a version.

The remote credentials provider (`credentials_provider` and everything below it) is read as one block, from the highest priority level that sets it under either name (`s3` wins inside a same level): rename all its parameters at once.

## Moving a Docker deployment from Silo or MinIO to RustFS

Every command of this section, the notes and the rollback included, runs in the folder of the compose file and in one shell, with the compose files you start the stack with selected first. If your Docker commands need `sudo`, open a root shell in that folder first (`sudo -s`). With the reference compose file:

```bash
export COMPOSE_FILE=docker-compose.yml
```

With the OpenSearch variant:

```bash
export COMPOSE_FILE=docker-compose.opensearch.yml
```

If you add other files with `-f`, list them all in `COMPOSE_FILE`, separated by `:`, in the same order. Step 1 checks that the storage container was created by exactly these files and stops otherwise.

This section only concerns deployments that run Silo or MinIO next to OpenCTI with Docker Compose and a named volume, like the reference deployment. A deployment using AWS S3 or another managed object storage has nothing to do. For Docker swarm or a bind-mounted data folder, adapt the commands (stop the storage service, back up and change the ownership of its data folder) or use option 1.

The compose files of [OpenCTI-Platform/docker](https://github.com/OpenCTI-Platform/docker) for OpenCTI 7.26XXXX.0 run RustFS on the same volume as before. Two paths exist to move the data. Whichever you choose, **back up the data volume first**.

!!! note "Already updated the compose file?"

    If you already started the stack with the compose file of OpenCTI 7.26XXXX.0 and the `minio` service keeps restarting (`docker compose logs minio` shows `Permission denied`), your data is unchanged. Put back the previous definition of the `minio` service only (from your own copy, or from the history of [docker-compose.yml](https://github.com/OpenCTI-Platform/docker/commits/master/docker-compose.yml) or [docker-compose.opensearch.yml](https://github.com/OpenCTI-Platform/docker/commits/master/docker-compose.opensearch.yml)) and keep the other services as they are (in a git clone, restore the file with `git checkout -- <file>` before the pull of step 3), then start at the beginning of option 2, or follow option 1.

### Option 1 (recommended by RustFS): copy the data to a new RustFS volume

Run RustFS on a new volume next to MinIO or Silo, copy the buckets with `mc mirror`, then point OpenCTI to RustFS: in the compose file of OpenCTI 7.26XXXX.0, mount the new volume on the `minio` service instead of `s3data`. Declare it as an external volume, otherwise Compose prefixes its name with the project name (`xtm_` in the reference `.env`) and mounts a new, empty volume:

```yaml
services:
  minio:
    volumes:
      - rustfsdata:/data
volumes:
  rustfsdata:
    external: true
    name: <name of the volume you copied the buckets to>
```

After starting it, check that `docker inspect -f '{{range .Mounts}}{{if eq .Destination "/data"}}{{.Name}}{{end}}{{end}}' "$(docker compose ps -q minio)"` shows that volume. This path needs a second volume of the same size and a short write freeze during the final copy. According to the RustFS guide, `mc mirror` copies the current version of each object only: the version history is lost, tags, metadata and bucket settings must be checked after the copy, and users and policies must be recreated on RustFS. Follow the [RustFS migration guide](https://rustfs.com/blog/migrating-from-minio-to-rustfs-a-technical-guide/).

### Option 2 (not supported by RustFS, tested by Filigran): start RustFS on the existing volume

The RustFS migration guide states: "Do not point a current rustfs/rustfs image at a MinIO data directory and treat that as the migration." As of RustFS 1.0.4 (October 2026), its README presents MinIO on-disk compatibility as a preview "gated behind the `rio-v2` feature and not part of the default build", while its [file format compatibility page](https://github.com/rustfs/rustfs/blob/1.0.4/docs/architecture/minio-file-format-compat.md) lists unencrypted objects, bucket metadata and identities as read and imported by the released images.

Filigran tested this path with RustFS 1.0.4 on data written by Silo `RELEASE.2026-10-18T00-00-00Z`, on a single node and on a 3-node cluster: buckets, objects, versions, metadata, users, policies and service accounts were kept, and reads, writes and deletes worked after the move. Use it only if you accept to run outside the RustFS support scope, with a backup at hand.

Prerequisites:

- Data written by Silo, or by a MinIO version close to the one tested. A user reported that RustFS 1.0.0-rc.3 did not see objects written by a MinIO from 2021, even after a MinIO upgrade ([rustfs#6657](https://github.com/rustfs/rustfs/issues/6657)). For a long-lived MinIO deployment, use option 1. Steps 1 and 5 below count the objects to detect such a case.
- No objects encrypted by the server (SSE-S3, SSE-KMS, SSE-C). RustFS does not read MinIO encrypted objects, and the object count below does not detect them: they are still listed.
- The same root credentials as before. Some MinIO identity data is signed or encrypted with keys derived from them.

Steps 1 and 2 run with the compose file you use today. If you update a clone of OpenCTI-Platform/docker with `git pull`, run them before the pull; if you already pulled and started the stack, see the note above.

Each block below checks that the previous ones succeeded and prints "stop here" instead of going on. If the shell is lost after step 4, go back with the rollback below. Host restarts restart the stopped services: do not reboot during the steps. The images `pgsty/silo:RELEASE.2026-10-18T00-00-00Z` and `alpine` must be reachable (pull them first on an offline host).

1. Check the selection, check that the storage volume holds MinIO or Silo data, stop everything but the storage service and count the objects (the count retries for up to one minute while the service starts). The client is the Silo image, which ships the MinIO client (`mcli`). The credentials are read from the configuration of the storage container; if your compose file passes them another way, set `S3_USER` and `S3_PASSWORD` before this step:

    ```bash
    STEP1_OK=; N1=; S3_VOLUME=
    SELECTED=$(IFS=:; for f in $COMPOSE_FILE; do printf '%s,' "$(cd "$(dirname "$f")" && pwd)/$(basename "$f")"; done); SELECTED=${SELECTED%,}
    MINIO_ID=$(docker compose ps -aq minio)
    if [ -n "$COMPOSE_FILE" ] && [ -n "$MINIO_ID" ] && [ "$(docker inspect -f '{{index .Config.Labels "com.docker.compose.project.config_files"}}' "$MINIO_ID")" = "$SELECTED" ]; then
      S3_VOLUME=$(docker inspect -f '{{range .Mounts}}{{if eq .Destination "/data"}}{{.Name}}{{end}}{{end}}' "$MINIO_ID")
      if [ -n "$S3_VOLUME" ] && docker run --rm -v "$S3_VOLUME":/data alpine test -d /data/.minio.sys; then
        docker compose stop
        docker compose up -d minio
        S3_ENV=$(docker inspect -f '{{range .Config.Env}}{{println .}}{{end}}' "$(docker compose ps -q minio)")
        export S3_USER=${S3_USER:-$(printf '%s\n' "$S3_ENV" | sed -n 's/^MINIO_ROOT_USER=//p')}
        export S3_PASSWORD=${S3_PASSWORD:-$(printf '%s\n' "$S3_ENV" | sed -n 's/^MINIO_ROOT_PASSWORD=//p')}
        count_objects() { docker run --rm --network container:"$(docker compose ps -q minio)" -e S3_USER -e S3_PASSWORD --entrypoint sh pgsty/silo:RELEASE.2026-10-18T00-00-00Z -c 'set -o pipefail; mcli --quiet alias set s3 http://localhost:9000 "$S3_USER" "$S3_PASSWORD" >/dev/null && mcli --quiet ls -r --versions s3/ | wc -l'; }
        for i in $(seq 30); do N1=$(count_objects) && break; N1=; sleep 2; done
        [ -n "$N1" ] && STEP1_OK=1 && echo "$S3_VOLUME: $N1 objects" || echo "count failed, stop here"
      else
        echo "the storage volume holds no MinIO or Silo data, stop here"
      fi
    else
      echo "no storage container created by the selected files in this project: check the selection (if you removed the container, recreate it with docker compose create minio), stop here"
    fi
    ```

2. Stop the storage service, back up its volume, and check the archive. The command refuses to overwrite an existing `s3data.tar.gz`: move a previous one away first. It also writes the volume name to `s3data.volume`, used by the rollback. The archive holds every stored file and the storage identities: keep it out of reach.

    ```bash
    BACKUP_OK=
    if [ "${STEP1_OK:-}" = 1 ] && [ ! -e s3data.tar.gz ]; then
      docker compose stop minio
      docker run --rm -v "$S3_VOLUME":/data -v "$(pwd)":/backup alpine tar czf /backup/s3data.tar.gz -C /data . && gzip -t s3data.tar.gz && echo "$S3_VOLUME" > s3data.volume && BACKUP_OK=1 && ls -l s3data.tar.gz
    fi
    [ "$BACKUP_OK" = 1 ] || echo "no backup (step 1 did not succeed, or s3data.tar.gz already exists), stop here"
    ```

3. Keep a copy of the current compose file (needed to go back), then update it to OpenCTI 7.26XXXX.0 or later and pull the new images. Keep your `.env` file: the root credentials are reused as they are.

    ```bash
    docker compose pull
    ```

4. Give the volume to the RustFS user. The RustFS image does not run as root, and a volume written by MinIO or Silo belongs to root: without this step RustFS stops at startup with `Permission denied`.

    ```bash
    CHOWN_OK=
    [ "${BACKUP_OK:-}" = 1 ] && docker run --rm -v "$S3_VOLUME":/data alpine chown -R 10001:10001 /data && CHOWN_OK=1 && echo "volume given to RustFS" || echo "no backup made in step 2, stop here"
    ```

5. Start RustFS alone (the command returns once it is healthy, and fails if it turns unhealthy or after 5 minutes), check that it uses the backed-up volume, then count the objects again (the count retries for up to one minute):

    ```bash
    STEP5_OK=; N2=
    if [ "${CHOWN_OK:-}" = 1 ] && docker compose up -d --wait --wait-timeout 300 minio && [ "$(docker inspect -f '{{range .Mounts}}{{if eq .Destination "/data"}}{{.Name}}{{end}}{{end}}' "$(docker compose ps -q minio)")" = "$S3_VOLUME" ]; then
      for i in $(seq 30); do N2=$(count_objects) && [ "$N2" = "$N1" ] && break; N2=; sleep 2; done
      [ -n "$N2" ] && [ "$N2" = "$N1" ] && STEP5_OK=1 && echo "$S3_VOLUME: $N2 objects, same count"
    fi
    [ "$STEP5_OK" = 1 ] || echo "RustFS not healthy, not on the backed-up volume, or count differs: stop here and go back"
    ```

6. Start the stack, then check the files: in OpenCTI, download a file attached to an entity, then upload a new one. If XTM One runs in the same stack, open a conversation with an attached file.

    ```bash
    [ "${STEP5_OK:-}" = 1 ] && docker compose up -d || echo "step 5 did not succeed, do not start the stack"
    ```

After the move, RustFS logs a warning such as `Ignoring unknown persisted scalar config key` every few seconds, about settings stored by MinIO or Silo. It is harmless, but the default Docker log driver does not rotate logs: set a rotation on the service (`logging.options.max-size`) if you keep it running that way.

#### Going back

The move is one way: RustFS adds its own metadata to the volume, and going back to MinIO or Silo is not supported. Going back means restoring the backup of step 2: the files written since the move are lost.

1. Stop the stack and restore the backup into the storage volume. The volume is found again as in step 1 and must be the one recorded in `s3data.volume`, so this works from a new shell (select the compose files first):

    ```bash
    docker compose stop
    docker compose create minio >/dev/null
    S3_VOLUME=$(docker inspect -f '{{range .Mounts}}{{if eq .Destination "/data"}}{{.Name}}{{end}}{{end}}' "$(docker compose ps -aq minio)")
    [ -n "$S3_VOLUME" ] && [ "$S3_VOLUME" = "$(cat s3data.volume)" ] && gzip -t s3data.tar.gz && docker run --rm -v "$S3_VOLUME":/data -v "$(pwd)":/backup alpine sh -c 'test -s /backup/s3data.tar.gz && rm -rf /data/* /data/.[!.]* && tar xzf /backup/s3data.tar.gz -C /data' && echo "restored into $S3_VOLUME" || echo "restore failed or not the backed-up volume, stop here"
    ```

2. Put back the storage service definition from the copy of step 3 (keep the OpenCTI version you run, its data migrations have already been applied), then start the stack. `up -d` recreates the storage service from that definition:

    ```bash
    docker compose up -d
    ```

### Own compose file

If you maintain your own compose file, the storage service becomes the following. Keep your existing `ports:` and `networks:` entries, and the service name `minio` if OpenCTI reaches it by that name.

```yaml
  minio:
    image: rustfs/rustfs:1.0.4
    volumes:
      - s3data:/data
    environment:
      RUSTFS_ACCESS_KEY: ${MINIO_ROOT_USER}
      RUSTFS_SECRET_KEY: ${MINIO_ROOT_PASSWORD}
      RUSTFS_OBS_LOG_DIRECTORY: "" # logs to stdout (docker logs) instead of files inside the container
    restart: always
    healthcheck:
      test: ["CMD", "curl", "-f", "http://localhost:9000/health/ready"]
      interval: 10s
      timeout: 5s
      retries: 3
      start_period: 60s
```

Remove the former `command:` line, and replace a healthcheck based on `mc`: the RustFS image does not contain it.

## Useful links

- [RustFS documentation](https://docs.rustfs.com/)
- [RustFS migration guide from MinIO](https://rustfs.com/blog/migrating-from-minio-to-rustfs-a-technical-guide/)
- [MinIO data format compatibility in RustFS 1.0.4](https://github.com/rustfs/rustfs/blob/1.0.4/docs/architecture/minio-file-format-compat.md)
- [RustFS health check endpoints](https://docs.rustfs.com/en/operations/status-check)
