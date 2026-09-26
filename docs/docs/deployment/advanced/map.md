# Map Configuration

## Introduction

OpenCTI renders maps locally in the browser using vector tiles from a [PMTiles](https://pmtiles.io/) file. No external map server is required.

## How it works

A map is drawn from two independent files.

The **tiles** carry the base map, served from a backend endpoint (`/maps/world.pmtiles`) that supports HTTP Range requests. The browser fetches only the tile data it needs for the current viewport and zoom level.

The **country boundaries** are the polygons used to colour countries in map widgets, served as GeoJSON from `/maps/countries.json`.

Each file has two possible sources:

- **Bundled** (default) — the file shipped inside the Docker image.
- **Custom** — a file uploaded by an administrator and stored in the S3 bucket (Silo or any S3-compatible storage).

When a custom file has been uploaded, it is used; otherwise, the bundled file is used. The two files are independent: replacing one does not replace the other.

## Default behavior

Out of the box, OpenCTI uses the bundled PMTiles file included in the Docker image. No configuration, no S3 upload, and no external network access is required. This works for all environments, including air-gapped deployments.

The map adapts automatically to the platform theme (dark or light).

## Custom map data

Administrators can upload a custom `.pmtiles` file to replace the bundled map data with higher-resolution tiles or region-specific data.

### Uploading a custom PMTiles file

1. Obtain a `.pmtiles` file (see [PMTiles file sources](#pmtiles-file-sources) below).
2. Go to **Settings > Parameters > Map configuration**.
3. Click **Upload** next to **Custom map**.

The custom file is used immediately — no additional step required. It is stored in the S3 bucket; only one custom file can exist at a time, uploading a new file replaces the previous one.

### Reverting to the bundled map

Click **Delete** next to **Custom map** in **Settings > Parameters > Map configuration**. The platform immediately falls back to the bundled file.

## Custom country boundaries

The polygons used to colour countries in map widgets come from a GeoJSON file, separate from the tiles. Administrators can replace it the same way.

### Uploading a custom boundaries file

1. Prepare a GeoJSON `FeatureCollection`. Every feature must carry an `ISO3` property, which is how the platform matches a polygon to a country; `ISO2`, `NAME`, `LON` and `LAT` are also read. The file may be uploaded as plain GeoJSON or gzipped — the platform detects which and always stores it compressed.
2. Go to **Settings > Parameters > Map configuration**.
3. Click **Upload** next to **Custom country boundaries**.

The file is validated on upload: a file that is not valid JSON, is not a `FeatureCollection`, or has a feature without an `ISO3` property is rejected and the previous file is kept.

The bundled file is generated from the [Natural Earth](https://www.naturalearthdata.com/) `ne_10m_admin_0_countries` layer by `scripts/generate-countries-geojson.sh`, which can serve as a starting point for a custom one.

### Reverting to the bundled boundaries

Click **Delete** next to **Custom country boundaries**. The platform immediately falls back to the bundled file.

## Configuration

| Parameter                 | Environment variable       | Default value                | Description                              |
|:-------------------------|:--------------------------|:----------------------------|:----------------------------------------|
| app:map_bundled_file_path | APP__MAP_BUNDLED_FILE_PATH | `./static/maps/world.pmtiles` | Path to the bundled PMTiles file on disk |
| app:map_countries_bundled_file_path | APP__MAP_COUNTRIES_BUNDLED_FILE_PATH | `./static/maps/countries.json` | Path to the bundled country boundaries GeoJSON file on disk |

Maps work out of the box with no configuration needed.

The `map_bundled_file_path` and `map_countries_bundled_file_path` parameters allow overriding the location of the bundled files. This is mainly useful for development or custom Docker images.

## PMTiles file sources

The planet vector tile builds are available daily from [Protomaps](https://protomaps.com/):

- **Daily builds**: `https://build.protomaps.com/YYYYMMDD.pmtiles` (full planet, ~137 GB)

For OpenCTI, a **low-zoom extract** (zoom 0–6, ~30–80 MB) is sufficient. Generate one with the [go-pmtiles](https://github.com/protomaps/go-pmtiles) CLI:

```bash
pmtiles extract https://build.protomaps.com/20260722.pmtiles world.pmtiles --maxzoom=6
```

This uses HTTP Range requests — it does **not** download the full 137 GB file.

Other options:

- [Protomaps CLI](https://docs.protomaps.com/guide/getting-started) — Create regional extracts with `--bbox`.
- [planetiler](https://github.com/onthegomap/planetiler) — Build tiles from raw OpenStreetMap data.

## Migration from external tile server

If you previously used the `map_tile_server_dark` / `map_tile_server_light` configuration to point to an external raster tile server (e.g., `klokantech/openmaptiles-server`), those settings are no longer used. The platform now renders maps locally. You can safely remove the external tile server from your deployment.

The deprecated configuration parameters (`APP__MAP_TILE_SERVER_DARK`, `APP__MAP_TILE_SERVER_LIGHT`) are ignored.