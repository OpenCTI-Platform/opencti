/*
 * Builds the vendor taxonomy dictionary shipped with the curation module
 * (src/modules/curation/data/vendor-taxonomy.json).
 *
 * Sources (each cluster keeps its own provenance, clusters are never chained together):
 * - MITRE ATT&CK Enterprise (intrusion sets, campaigns, malware and tools with their aliases).
 *   (c) The MITRE Corporation, reproduced and distributed with the permission of The MITRE Corporation.
 * - MISP galaxy "threat-actor" cluster (vendor naming aggregated from vendor reports and the ETDA threat group cards)
 *   and "malpedia" cluster (Malpedia family synonyms), dual-licensed CC0 1.0 / BSD 2-Clause.
 *
 * Usage: node script/build-curation-taxonomy.ts
 * Local files can replace the downloads: CURATION_TAXONOMY_ATTACK, CURATION_TAXONOMY_MISP_ACTORS, CURATION_TAXONOMY_MISP_MALPEDIA.
 */
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

type ClusterKind = 'actor' | 'software' | 'campaign';
interface TaxonomyCluster {
  k: ClusterKind;
  n: string[];
  r: string;
}

const ATTACK_URL = 'https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master/enterprise-attack/enterprise-attack.json';
const MISP_ACTORS_URL = 'https://raw.githubusercontent.com/MISP/misp-galaxy/main/clusters/threat-actor.json';
const MISP_MALPEDIA_URL = 'https://raw.githubusercontent.com/MISP/misp-galaxy/main/clusters/malpedia.json';

const loadJson = async (envKey: string, url: string): Promise<any> => {
  const localPath = process.env[envKey];
  if (localPath) {
    return JSON.parse(fs.readFileSync(localPath, 'utf-8'));
  }
  const response = await fetch(url);
  if (!response.ok) {
    throw new Error(`Cannot download ${url}: HTTP ${response.status}`);
  }
  return response.json();
};

const cleanNames = (names: unknown[]): string[] => {
  const seen = new Set<string>();
  const result: string[] = [];
  names.forEach((value) => {
    if (typeof value !== 'string') return;
    const name = value.trim();
    const key = name.toLowerCase();
    if (name.length < 2 || name.length > 120 || seen.has(key)) return;
    seen.add(key);
    result.push(name);
  });
  return result;
};

const fromAttack = (bundle: any): TaxonomyCluster[] => {
  const clusters: TaxonomyCluster[] = [];
  (bundle.objects ?? []).forEach((object: any) => {
    if (object.revoked || object.x_mitre_deprecated) return;
    const mitreId = (object.external_references ?? []).find((ref: any) => ref.source_name === 'mitre-attack')?.external_id;
    if (!mitreId) return;
    let kind: ClusterKind | undefined;
    let names: unknown[] = [];
    if (object.type === 'intrusion-set') {
      kind = 'actor';
      names = [object.name, ...(object.aliases ?? [])];
    } else if (object.type === 'campaign') {
      kind = 'campaign';
      names = [object.name, ...(object.aliases ?? [])];
    } else if (object.type === 'malware' || object.type === 'tool') {
      kind = 'software';
      names = [object.name, ...(object.x_mitre_aliases ?? [])];
    }
    if (!kind) return;
    const cleaned = cleanNames(names);
    if (cleaned.length > 1) {
      clusters.push({ k: kind, n: cleaned, r: `mitre:${mitreId}` });
    }
  });
  return clusters;
};

const fromMispGalaxy = (galaxy: any, kind: ClusterKind, prefix: string): TaxonomyCluster[] => {
  const clusters: TaxonomyCluster[] = [];
  (galaxy.values ?? []).forEach((value: any) => {
    const cleaned = cleanNames([value.value, ...(value.meta?.synonyms ?? [])]);
    if (cleaned.length > 1 && value.uuid) {
      clusters.push({ k: kind, n: cleaned, r: `${prefix}:${value.uuid}` });
    }
  });
  return clusters;
};

const build = async () => {
  const [attack, mispActors, mispMalpedia] = await Promise.all([
    loadJson('CURATION_TAXONOMY_ATTACK', ATTACK_URL),
    loadJson('CURATION_TAXONOMY_MISP_ACTORS', MISP_ACTORS_URL),
    loadJson('CURATION_TAXONOMY_MISP_MALPEDIA', MISP_MALPEDIA_URL),
  ]);
  const clusters = [
    ...fromAttack(attack),
    ...fromMispGalaxy(mispActors, 'actor', 'misp-threat-actor'),
    ...fromMispGalaxy(mispMalpedia, 'software', 'misp-malpedia'),
  ].sort((a, b) => a.r.localeCompare(b.r));
  const output = {
    version: new Date().toISOString().slice(0, 10),
    sources: [
      { id: 'mitre', name: 'MITRE ATT&CK Enterprise', license: 'ATT&CK Terms of Use - (c) The MITRE Corporation, reproduced with permission', url: ATTACK_URL },
      { id: 'misp-threat-actor', name: 'MISP galaxy threat-actor (vendor naming incl. ETDA threat group cards)', license: 'CC0 1.0 or BSD 2-Clause', url: MISP_ACTORS_URL },
      { id: 'misp-malpedia', name: 'MISP galaxy malpedia (Malpedia family synonyms)', license: 'CC0 1.0 or BSD 2-Clause', url: MISP_MALPEDIA_URL },
    ],
    clusters,
  };
  const dirname = path.dirname(fileURLToPath(import.meta.url));
  const target = path.join(dirname, '../src/modules/curation/data/vendor-taxonomy.json');
  fs.mkdirSync(path.dirname(target), { recursive: true });
  fs.writeFileSync(target, `${JSON.stringify(output)}\n`);
  console.info(`Vendor taxonomy written to ${target} (${clusters.length} clusters)`);
};

build().catch((error) => {
  console.error(error);
  process.exit(1);
});
