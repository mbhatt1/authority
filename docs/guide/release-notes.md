# Release Process & Notes

## Nanos Releases

To release a new version of Nanos:

1. Create a [GitHub release](https://github.com/mbhatt1/authority/releases)
2. Build the source on both Linux and macOS
3. Run the release script:
   ```bash
   ./release.sh
   ```

## Ops Releases

For Authority Ops releases, see the [Ops release.sh](https://github.com/nanovms/ops/blob/master/release.sh) documentation.

## Package Updates

Follow the PACKAGES.md documentation to update packages.

## How End-Users Get Updates

Currently, we do not push updates automatically to users. Users must request updates:

### Updating Ops

```bash
ops update
```

### Updating Authority

```bash
authority run/load -f
```

The `-f` flag forces fetching the latest version.

## Release Channels

Releases are published on GitHub. Check the [Releases page](https://github.com/mbhatt1/authority/releases) for the latest versions.
