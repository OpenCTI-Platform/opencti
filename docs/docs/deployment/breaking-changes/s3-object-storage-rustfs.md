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

This section only concerns deployments that run Silo or MinIO next to OpenCTI with Docker Compose and a named volume, like the reference deployment. A deployment using AWS S3 or another managed object storage has nothing to do.

The compose file of [OpenCTI-Platform/docker](https://github.com/OpenCTI-Platform/docker) for OpenCTI 7.26XXXX.0 runs RustFS on the same `s3data` volume as before. Moving the data is described by RustFS: start with the [RustFS migration guide](https://rustfs.com/blog/migrating-from-minio-to-rustfs-a-technical-guide/) and the [RustFS documentation](https://docs.rustfs.com/). This page gives the main steps and what to know for an OpenCTI deployment; it is not a complete procedure.

!!! warning "Back up first: the move is one way"

    Whichever path you choose, back up the storage volume before the move. RustFS adds its own metadata to the volume and going back to MinIO or Silo is not supported: going back means restoring that backup, and the files written since the move are lost.

!!! note "Already started the new compose file?"

    If you started the stack with the compose file of OpenCTI 7.26XXXX.0 without moving the data, the `minio` service keeps restarting (`docker compose logs minio` shows `Permission denied`) and OpenCTI waits for it. Your data is unchanged: put back the previous definition of the `minio` service, start it again, then follow one of the paths below.

If you start the stack with the OpenSearch variant (`-f docker-compose.opensearch.yml`), with `-p` or with other `-f` options, use the same options for every command below. If you update a clone of OpenCTI-Platform/docker with `git pull`, do the steps that use the current storage (backup, count) before the pull.

### Option 1 (recommended by RustFS): copy the data to a new RustFS volume

Run RustFS on a new volume next to MinIO or Silo, copy the buckets with `mc mirror`, then mount the new volume on the `minio` service in the compose file of OpenCTI 7.26XXXX.0, instead of `s3data`. It needs a second volume of the same size and a short write freeze during the final copy. According to the RustFS guide, `mc mirror` copies the current version of each object only: the version history is lost, tags, metadata and bucket settings must be checked after the copy, and users and policies must be recreated on RustFS.

Declare the new volume as an external volume, otherwise Compose prefixes its name with the project name (`xtm_` with the reference `.env`) and mounts a new, empty volume:

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

### Option 2 (not supported by RustFS, tested by Filigran): start RustFS on the existing volume

!!! danger "Outside the RustFS support scope"

    The RustFS migration guide states: "Do not point a current rustfs/rustfs image at a MinIO data directory and treat that as the migration." Use this path only with a backup at hand.

As of RustFS 1.0.4 (October 2026), its README presents MinIO on-disk compatibility as a preview "gated behind the `rio-v2` feature and not part of the default build", while its [file format compatibility page](https://github.com/rustfs/rustfs/blob/1.0.4/docs/architecture/minio-file-format-compat.md) lists unencrypted objects, bucket metadata and identities as read and imported by the released images. Filigran tested this path with RustFS 1.0.4 on data written by Silo `RELEASE.2026-10-18T00-00-00Z`, on a single node and on a 3-node cluster: buckets, objects, versions, metadata, users, policies and service accounts were kept, and reads, writes and deletes worked after the move.

Prerequisites:

- Data written by Silo, or by a MinIO version close to the one tested. A user reported that RustFS 1.0.0-rc.3 did not see objects written by a MinIO from 2021, even after a MinIO upgrade ([rustfs#6657](https://github.com/rustfs/rustfs/issues/6657)). For a long-lived MinIO deployment, use option 1.
- No objects encrypted by the server (SSE-S3, SSE-KMS, SSE-C): RustFS does not read MinIO encrypted objects.
- The same root credentials as before: some MinIO identity data is signed or encrypted with keys derived from them.

Main steps:

1. Count the objects of the current storage, to compare after the move (for example with the MinIO client: `mc ls --recursive --versions`).
2. Stop the stack, then back up the storage volume (for example a `tar` archive of the volume made from a temporary container) and check the archive. Keep it out of reach: it holds every stored file and the storage identities.
3. Keep a copy of the current compose file, then update it to OpenCTI 7.26XXXX.0 or later and pull the new images. Keep your `.env` file: the root credentials are reused as they are.
4. Give the volume to the RustFS user: the RustFS image runs as uid 10001, and a volume written by MinIO or Silo belongs to root, so RustFS stops at startup with `Permission denied` until then. For example: `docker run --rm -v <volume>:/data alpine chown -R 10001:10001 /data`.
5. Start the storage service alone, wait until it is healthy, check that it uses the backed-up volume, and count the objects again: the count must be the same. If it is not, go back before starting anything else.
6. Start the stack, then check the files: in OpenCTI, download a file attached to an entity and upload a new one. If XTM One runs in the same stack, open a conversation with an attached file.

After the move, RustFS logs a warning such as `Ignoring unknown persisted scalar config key` every few seconds, about settings stored by MinIO or Silo. It is harmless, but the default Docker log driver does not rotate logs: set a rotation on the service (`logging.options.max-size`) if you keep it running that way.

Going back is only possible with the backup of step 2: stop the stack, restore the archive into the storage volume (it then belongs to root again), put back the storage service definition from the copy of step 3, keep the OpenCTI version you run (its data migrations have already been applied), then start the stack. The files written since the move are lost.

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
