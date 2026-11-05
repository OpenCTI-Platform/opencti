import { createHash } from 'node:crypto';
import { existsSync, readFileSync } from 'node:fs';
import { join } from 'node:path';
import jsonCanonicalize from 'canonicalize';
import { v5 as uuidv5 } from 'uuid';
import { ImportClientError, type ImportClient, UploadFile } from '../../../src/intake/stix-import/types';
import { answerOperation, describeOperation } from '../../../src/intake/dry-intake/simulated-answers';

// The platform as the client-python recorder simulates it (tests/import_conformance/recorder.py):
// records each call as it would leave the wire and answers from the fixture's world. Any change
// here or in the answers (src/intake/dry-intake/simulated-answers.ts) must be made in the
// recorder too, the ids and answers of both sides must be identical.

export const RESPONSE_ID_NAMESPACE = '4a8a4c2e-6a53-4c1b-9e43-0f2f1c8a6b10';
const WORLD_DIR = join(__dirname, '../../../../../client-python/tests/data/import-conformance/world');

export interface RecordedCall {
  seq: number;
  op: string;
  name: string | null;
  root: string;
  sub: string | null;
  variables: unknown;
  files: { path: string; name: string; mime: string; sha256: string }[];
}

// Every document the port sent, to validate them against the platform schema
export const SEEN_DOCUMENTS = new Set<string>();

// Every call the port sent, with its variables as sent (files kept as UploadFile, undefined keys
// dropped), to coerce them against the platform schema
export interface SeenCall {
  fixtureDir: string;
  document: string;
  variables: Record<string, unknown>;
}
export const SEEN_CALLS: SeenCall[] = [];

// A copy of the variables as they leave the wire, files kept: the port may change its objects later
const copyVariables = (value: unknown): unknown => {
  if (value instanceof UploadFile) {
    return value;
  }
  if (Array.isArray(value)) {
    return value.map(copyVariables);
  }
  if (value !== null && typeof value === 'object') {
    return Object.fromEntries(Object.entries(value).filter(([, item]) => item !== undefined).map(([key, item]) => [key, copyVariables(item)]));
  }
  return value;
};

export const responseId = (root: string, sub: string | null, variables: unknown) => {
  return uuidv5(`${sub ? `${root}.${sub}` : root}:${jsonCanonicalize(variables)}`, RESPONSE_ID_NAMESPACE);
};

// pycti _extract_files then the JSON encoding: files become null, undefined keys disappear
const extractFiles = (variables: Record<string, unknown>) => {
  const files: RecordedCall['files'] = [];
  let mapIndex = 0;
  const walk = (value: unknown, path: string): unknown => {
    if (value instanceof UploadFile) {
      files.push({ path, name: value.name, mime: value.mime, sha256: createHash('sha256').update(value.data).digest('hex') });
      mapIndex += 1;
      return null;
    }
    if (Array.isArray(value)) {
      if (value.length > 0 && value.every((item) => item instanceof UploadFile)) {
        return value.map((file: UploadFile) => {
          files.push({ path: `${path}.${mapIndex}`, name: file.name, mime: file.mime, sha256: createHash('sha256').update(file.data).digest('hex') });
          mapIndex += 1;
          return null;
        });
      }
      return value.map((item, index) => walk(item, path ? `${path}.${index}` : String(index)));
    }
    if (value !== null && typeof value === 'object') {
      return Object.fromEntries(Object.entries(value)
        .filter(([, item]) => item !== undefined)
        .map(([key, item]) => [key, walk(item, path ? `${path}.${key}` : key)]));
    }
    return value;
  };
  const cleaned = walk(variables, '');
  return { variables: JSON.parse(JSON.stringify(cleaned)), files };
};

export class RecordingClient implements ImportClient {
  readonly calls: RecordedCall[] = [];

  private readonly fixtureDir: string;

  private readonly reads: Record<string, unknown>;

  // Root fields the platform refuses: every call to them answers this GraphQL error
  private readonly errors: Record<string, { name: string; message: string }> = {};

  // track: add the documents and calls to SEEN_DOCUMENTS and SEEN_CALLS (the goldens' runs only)
  constructor(fixtureDir: string, private readonly track = true) {
    this.fixtureDir = fixtureDir;
    this.reads = { vocabularyCategories: JSON.parse(readFileSync(join(WORLD_DIR, 'vocabulary-categories.json'), 'utf-8')) };
    const worldFile = join(fixtureDir, 'world.json');
    if (existsSync(worldFile)) {
      const world = JSON.parse(readFileSync(worldFile, 'utf-8'));
      Object.assign(this.reads, world.reads ?? {});
      Object.assign(this.errors, world.errors ?? {});
    }
  }

  async query(document: string, rawVariables: Record<string, unknown> = {}) {
    if (this.track) {
      SEEN_DOCUMENTS.add(document);
      SEEN_CALLS.push({ fixtureDir: this.fixtureDir, document, variables: copyVariables(rawVariables) as Record<string, unknown> });
    }
    const operation = describeOperation(document);
    const { variables, files } = extractFiles(rawVariables);
    this.calls.push({ seq: this.calls.length + 1, op: operation.op, name: operation.name, root: operation.root, sub: operation.sub, variables, files });
    const error = this.errors[operation.root];
    if (error) {
      throw new ImportClientError(error.name, error.message);
    }
    return { [operation.root]: answerOperation(operation, variables, this.reads, () => responseId(operation.root, operation.sub, variables)) };
  }
}
