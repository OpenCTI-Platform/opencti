# /// script
# requires-python = ">=3.10"
# dependencies = ["geopandas", "pyogrio", "pmtiles", "mapbox-vector-tile"]
# ///
"""Copy the country names of world.pmtiles onto countries.json.

Run it after scripts/generate-countries-geojson.sh:

    uv run scripts/sync-country-names-from-pmtiles.py

The PMTiles places carry no ISO code, so countries are matched through their
Wikidata id, read from the Natural Earth admin 0 layer used to build
countries.json, then by English name for the places without a Wikidata id.
Only the NAME property is rewritten; the rest of the file stays byte for byte.
"""

import gzip
import json
import os
import sys
import tempfile
import urllib.request

import geopandas as gpd
import mapbox_vector_tile
from pmtiles.reader import Compression, MmapSource, all_tiles, deserialize_header

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
MAPS_DIR = os.path.join(REPO_ROOT, "opencti-platform", "opencti-graphql", "static", "maps")
COUNTRIES_PATH = os.path.join(MAPS_DIR, "countries.json")
PMTILES_PATH = os.path.join(MAPS_DIR, "world.pmtiles")
NATURAL_EARTH_URL = "https://naciscdn.org/naturalearth/10m/cultural/ne_10m_admin_0_countries.zip"
PROPERTIES_PREFIX = '      "properties": '


def read_pmtiles_countries():
    countries = {}
    with open(PMTILES_PATH, "rb") as file:
        get_bytes = MmapSource(file)
        is_gzip = deserialize_header(get_bytes(0, 127))["tile_compression"] == Compression.GZIP
        for _, data in all_tiles(get_bytes):
            tile = mapbox_vector_tile.decode(gzip.decompress(data) if is_gzip else data)
            for feature in tile.get("places", {}).get("features", []):
                properties = feature["properties"]
                name = properties.get("name:en") or properties.get("name")
                if properties.get("kind") == "country" and name:
                    countries.setdefault(properties.get("wikidata") or f"name:{name}", {"wikidata": properties.get("wikidata"), "name": name})
    return list(countries.values())


def read_natural_earth():
    with tempfile.TemporaryDirectory() as workdir:
        archive = os.path.join(workdir, "ne_10m_admin_0_countries.zip")
        urllib.request.urlretrieve(NATURAL_EARTH_URL, archive)
        rows = gpd.read_file(archive, ignore_geometry=True)
    rows["ISO3"] = rows["ISO_A3_EH"].where(rows["ISO_A3_EH"] != "-99", rows["ADM0_A3"])
    return rows[rows["ISO3"] != "-99"]


def match(natural_earth, pmtiles_countries):
    by_wikidata = {country["wikidata"]: country for country in pmtiles_countries if country["wikidata"]}
    claimed = {row.WIKIDATAID for row in natural_earth.itertuples() if row.WIKIDATAID in by_wikidata}
    unclaimed = [country for country in pmtiles_countries if country["wikidata"] not in claimed]
    matches = {}
    for row in natural_earth.itertuples():
        country = by_wikidata.get(row.WIKIDATAID)
        method = "wikidata"
        if country is None:
            known_names = {row.NAME, row.NAME_EN, row.NAME_LONG, row.ADMIN}
            country = next((candidate for candidate in unclaimed if candidate["name"] in known_names), None)
            method = "name"
        matches[row.Index] = (country, method)
    return matches


def main():
    pmtiles_countries = read_pmtiles_countries()
    natural_earth = read_natural_earth()
    matches = match(natural_earth, pmtiles_countries)
    target_names = {
        index: (country["name"] if country else natural_earth.loc[index, "NAME"])
        for index, (country, _) in matches.items()
    }

    with open(COUNTRIES_PATH, encoding="utf-8", newline="") as file:
        lines = file.readlines()

    updated, unchanged, not_in_pmtiles, not_in_natural_earth = [], [], [], []
    used = set()
    for line_index, line in enumerate(lines):
        if not line.startswith(PROPERTIES_PREFIX):
            continue
        ending = line[len(line.rstrip("\r\n")):]
        properties = json.loads(line[len(PROPERTIES_PREFIX):].rstrip("\r\n").rstrip(","))
        rows = [
            index for index, row in natural_earth.iterrows()
            if row["ISO3"] == properties["ISO3"] and index not in used
            and properties["NAME"] in (row["NAME"], target_names[index])
        ]
        if not rows:
            not_in_natural_earth.append(properties)
            continue
        used.add(rows[0])
        country, method = matches[rows[0]]
        if country is None:
            not_in_pmtiles.append((properties, natural_earth.loc[rows[0], "WIKIDATAID"]))
            continue
        if properties["NAME"] == country["name"]:
            unchanged.append(properties)
            continue
        updated.append((properties["ISO3"], properties["NAME"], country["name"], method))
        properties["NAME"] = country["name"]
        lines[line_index] = f"{PROPERTIES_PREFIX}{json.dumps(properties, separators=(', ', ': '))},{ending}"

    with open(COUNTRIES_PATH, "w", encoding="utf-8", newline="") as file:
        file.writelines(lines)

    matched = {id(country) for country, _ in matches.values() if country}
    pmtiles_only = [country for country in pmtiles_countries if id(country) not in matched]

    print(f"Updated ({len(updated)}):")
    for iso3, old, new, method in updated:
        print(f"  {iso3}  {old} -> {new}  [{method}]")
    print(f"Matched, name already aligned ({len(unchanged)}):")
    print("  " + ", ".join(properties["ISO3"] for properties in unchanged))
    print(f"In countries.json, not in the PMTiles ({len(not_in_pmtiles)}):")
    for properties, wikidata in not_in_pmtiles:
        print(f"  {properties['ISO3']}  {properties['NAME']}  ({wikidata})")
    print(f"In the PMTiles, not in countries.json ({len(pmtiles_only)}):")
    for country in pmtiles_only:
        print(f"  {country['name']}  ({country['wikidata'] or 'no wikidata'})")
    if not_in_natural_earth:
        print(f"In countries.json, not in Natural Earth ({len(not_in_natural_earth)}):")
        for properties in not_in_natural_earth:
            print(f"  {properties['ISO3']}  {properties['NAME']}")
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
