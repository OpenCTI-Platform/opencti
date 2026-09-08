#!/usr/bin/env bash
# generate-countries-geojson.sh
#
# Generates opencti-front/src/static/geo/countries.json from Natural Earth data.
# Uses the same Natural Earth package that Protomaps uses for its PMTiles boundaries,
# ensuring country polygons are aligned with the rendered map tiles.
#
# Requirements: python3, geopandas, pyogrio (pip install geopandas pyogrio)
#
# Usage: ./scripts/generate-countries-geojson.sh

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
OUTPUT="$REPO_ROOT/opencti-platform/opencti-front/src/static/geo/countries.json"

WORKDIR=$(mktemp -d)
trap 'rm -rf "$WORKDIR"' EXIT

echo "Downloading Natural Earth data..."
curl -sL -o "$WORKDIR/natural_earth_vector.gpkg.zip" \
  "https://naciscdn.org/naturalearth/packages/natural_earth_vector.gpkg.zip"

echo "Extracting GeoPackage..."
unzip -q -j "$WORKDIR/natural_earth_vector.gpkg.zip" "packages/natural_earth_vector.gpkg" -d "$WORKDIR"

echo "Generating countries.json..."
python3 << EOF
import geopandas as gpd
import json

gdf = gpd.read_file("$WORKDIR/natural_earth_vector.gpkg", layer="ne_10m_admin_0_countries")

# Use ISO_A3_EH (fewer gaps) with fallback to ADM0_A3
gdf['ISO3'] = gdf['ISO_A3_EH'].where(gdf['ISO_A3_EH'] != '-99', gdf['ADM0_A3'])
gdf = gdf[gdf['ISO3'] != '-99'].copy()

# ISO2 from ISO_A2_EH
gdf['ISO2'] = gdf['ISO_A2_EH'].where(gdf['ISO_A2_EH'] != '-99', '')

# No simplification — keep full Natural Earth 10m resolution for precise alignment
# with PMTiles tile boundaries

# Compute representative point for centroid (avoids geographic CRS warning)
result = gdf[['ISO3', 'ISO2', 'NAME', 'geometry']].copy()
centroids = result.geometry.representative_point()
result['LAT'] = centroids.y.round(4)
result['LON'] = centroids.x.round(4)

# Convert to GeoJSON
geojson = json.loads(result.to_json())

for feature in geojson['features']:
    props = feature['properties']
    feature['properties'] = {
        'ISO3': props['ISO3'],
        'ISO2': props['ISO2'] if props['ISO2'] else '',
        'NAME': props['NAME'],
        'LON': props['LON'],
        'LAT': props['LAT'],
    }

# Sort by ISO3
geojson['features'].sort(key=lambda f: f['properties']['ISO3'])

# Pretty format: structure indented, coordinate arrays compact (one line per ring)
def format_coordinates(geom_type, coords):
    if geom_type == 'Polygon':
        rings = [json.dumps(ring, separators=(', ', ', ')) for ring in coords]
        inner = ',\n          '.join(rings)
        return f'[\n          {inner}\n        ]'
    elif geom_type == 'MultiPolygon':
        polygons = []
        for polygon in coords:
            rings = [json.dumps(ring, separators=(', ', ', ')) for ring in polygon]
            inner = ', '.join(rings)
            polygons.append(f'[{inner}]')
        inner = ',\n          '.join(polygons)
        return f'[\n          {inner}\n        ]'
    return json.dumps(coords, separators=(', ', ', '))

lines = ['{', '  "type": "FeatureCollection",', '  "features": [']
for i, feature in enumerate(geojson['features']):
    comma = ',' if i < len(geojson['features']) - 1 else ''
    geom = feature['geometry']
    lines.append('    {')
    lines.append(f'      "type": "Feature",')
    lines.append(f'      "properties": {json.dumps(feature["properties"], separators=(", ", ": "))},')
    lines.append(f'      "geometry": {{')
    lines.append(f'        "type": "{geom["type"]}",')
    lines.append(f'        "coordinates": {format_coordinates(geom["type"], geom["coordinates"])}')
    lines.append(f'      }}')
    lines.append(f'    }}{comma}')
lines.append('  ]')
lines.append('}')

with open("$OUTPUT", 'w') as f:
    f.write('\n'.join(lines))
    f.write('\n')

print(f"Generated {len(geojson['features'])} countries -> $OUTPUT")
EOF

echo "Done. Size: $(du -h "$OUTPUT" | cut -f1)"
