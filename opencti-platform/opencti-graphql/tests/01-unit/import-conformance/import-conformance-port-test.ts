import { describe, expect, it } from 'vitest';
import { existsSync, readdirSync, readFileSync } from 'node:fs';
import { join, relative, sep } from 'node:path';
import { UploadFile } from '../../../src/intake/stix-import/types';
import { ACCEPTED_DIFFERENCES_FILE, DEFAULT_CALL, FIXTURES_DIR, transformMessage } from './import-conformance-utils';
import { Kind, type OperationDefinitionNode, parse, validate } from 'graphql';
import { getVariableValues } from 'graphql/execution/values';
import Upload from 'graphql-upload/Upload.mjs';
import '../../../src/modules/index';
import createSchema from '../../../src/graphql/schema';
import { SEEN_CALLS, SEEN_DOCUMENTS } from './import-conformance-client';

// The platform's STIX transformation against pycti's goldens: same calls (operation, variables,
// files, in the same order), same outcome per object, same objects set aside.

// Differences the platform does not reproduce (accepted-differences.json, shared with the
// client-python type gate), each declared with its fixture:
// - pycti defects: pycti crashes (rules_rescan_async, a list read as one reference...) where the
//   port does what pycti intends;
// - splitter divergences on malformed messages (fixtures of splitter-divergences/ and two of
//   missing/ and sdo/): the platform splitter is not a port of pycti's and is shared with the
//   publish path, so it is not changed. pycti's splitter fails on the whole bundle where the
//   platform one does not: no type, extensions or the OpenCTI extension not a dict, a list where
//   one reference is expected, a target_ref missing, a list (unhashable) used as a dict key (an
//   item of a _refs field, the extension id or x_opencti_id), an item of external_references or
//   kill_chain_phases that is not a dict (a string, a number); or the reverse: a _refs field,
//   external_references or kill_chain_phases given as a dict pycti iterates. Both fail with
//   another error name: no id, external_references or kill_chain_phases as a non empty dict, a
//   null item of external_references or kill_chain_phases. The platform splitter rewrites a
//   _refs field given as "" into [] (pycti sends the string).
// The test checks that pycti's golden still shows the declared result (so a pycti change is
// noticed) and that the port gives exactly the declared result. A declared call holds the keys it
// pins (root and sub at least).
interface AcceptedDifference {
  reason: string;
  pycti: { bundle_error?: string; items?: { id: string; outcome: string }[]; calls?: Record<string, unknown>[] };
  port: { calls: Record<string, unknown>[]; items: unknown[]; incompatible: unknown[]; bundle_error: string | null; logged_errors: string[] };
}
const ACCEPTED_DIFFERENCES: Record<string, AcceptedDifference> = JSON.parse(readFileSync(ACCEPTED_DIFFERENCES_FILE, 'utf-8'));

// The port's GraphQL documents, read from its source: each one must be sent by a fixture
const PORT_DIR = join(__dirname, '../../../src/intake/stix-import');
// Documents no input can reach, with the reason
const UNREACHABLE_DOCUMENTS: Record<string, string> = {};

// Calls whose variables the platform schema refuses, accepted per fixture with the reason and the
// refused variables (a variable and its path, as graphql-js names them): any other refusal fails
const SIMPLE_OBSERVABLE_ID = 'pycti sends the simple-observable id as is, the StixId scalar refuses its type';
const VALUE_AS_IS = 'pycti sends a value of the wrong type as is, the String scalar refuses it';
const INVALID_VARIABLES: Record<string, { reason: string; at: string[] }> = {
  'missing/report-source-name-null/malware.legacy': { reason: VALUE_AS_IS, at: ['$input.source_name'] },
  'missing/report-title-external-id-types/malware.legacy': { reason: VALUE_AS_IS, at: ['$input.external_id'] },
  'missing/report-title-name-not-str/malware.legacy': { reason: VALUE_AS_IS, at: ['$input.name'] },
  'missing/simple-observable-int-unicode-spaces/simple-observable.legacy': { reason: SIMPLE_OBSERVABLE_ID, at: ['$stix_id'] },
  'missing/simple-observable-unicode-digits/simple-observable.legacy': { reason: SIMPLE_OBSERVABLE_ID, at: ['$stix_id'] },
  'missing/vocabulary-value-dict/malware.legacy': { reason: VALUE_AS_IS, at: ['$input.name'] },
  'ops/merge/sources-dict.ext': { reason: 'pycti sends merge_source_ids given as a dict as is, the [String]! type refuses it', at: ['$stixObjectsIds'] },
  'sco/simple-observable/handwritten-as-number.legacy': { reason: SIMPLE_OBSERVABLE_ID, at: ['$stix_id'] },
  'sco/simple-observable/handwritten-ipv4-value.ext': { reason: SIMPLE_OBSERVABLE_ID, at: ['$stix_id'] },
  'sco/simple-observable/handwritten-ipv4-value.legacy': { reason: SIMPLE_OBSERVABLE_ID, at: ['$stix_id'] },
  'sdo/malware/handwritten-external-reference-external-id-zero.legacy': { reason: VALUE_AS_IS, at: ['$input.external_id'] },
  'splitter-divergences/malware/created-by-ref-as-list.legacy': {
    reason: 'the port sends created_by_ref given as a list as is (pycti fails before, in its splitter), the String scalar refuses it',
    at: ['$input.createdBy'],
  },
  'splitter-divergences/malware/object-marking-refs-list-item.legacy': {
    reason: 'the port sends an object_marking_refs item given as a list as is (pycti fails before, in its splitter), the String scalar refuses it',
    at: ['$input.objectMarking[0]'],
  },
  'variants-review/simple-observable-proto-key/simple-observable.legacy': { reason: SIMPLE_OBSERVABLE_ID, at: ['$stix_id'] },
};
// The fixtures of missing/ send the null pycti sends for a missing required field: there, a null
// (or an absent required field) refused by a non-null type is accepted (graphql-js 17 wording)
const MISSING_REQUIRED_VALUE = [
  /: Expected value of non-null type "[^"]+!" not to be null\.$/,
  /: Expected a value of non-null type "[^"]+!" to be provided\.$/,
  /: Expected value of type "[^"]+" to include required field "[^"]+", found: /,
];
const isMissingRequiredValue = (fixture: string, message: string) => fixture.startsWith('missing/')
  && MISSING_REQUIRED_VALUE.some((pattern) => pattern.test(message));
// The refused variable of a graphql-js coercion error: `$input.source_name`, `$stix_id`
const refusedVariable = (message: string) => {
  const match = /^Variable "(\$\w+)" has invalid value(?: at ([^:]+))?:/.exec(message);
  return match ? `${match[1]}${match[2] ?? ''}` : message;
};

const normalizeDocument = (document: string) => document.replace(/\s+/g, ' ').trim();

const fixtures = (readdirSync(FIXTURES_DIR, { recursive: true }) as string[])
  .filter((path) => existsSync(join(FIXTURES_DIR, path, 'expected.json')))
  .map((path) => path.split(sep).join('/'))
  .sort();

const readJson = (dir: string, file: string) => JSON.parse(readFileSync(join(dir, file), 'utf-8'));

// The declared keys of each call (root and sub when the call is not declared)
const pinnedCalls = (calls: Record<string, unknown>[], declared: Record<string, unknown>[]) => calls.map((call, index) => {
  const keys = Object.keys(declared[index] ?? { root: null, sub: null });
  return Object.fromEntries(keys.map((key) => [key, call[key]]));
});

const transformFixture = async (fixture: string) => {
  const dir = join(FIXTURES_DIR, fixture);
  const call = { ...DEFAULT_CALL, ...(existsSync(join(dir, 'call.json')) ? readJson(dir, 'call.json') : {}) };
  return transformMessage(dir, call, readJson(dir, 'input.json'));
};

describe('Import conformance: the platform port against pycti', () => {
  it.each(fixtures)('%s', async (fixture) => {
    const expected = readJson(join(FIXTURES_DIR, fixture), 'expected.json');
    const actual = await transformFixture(fixture);
    const accepted = ACCEPTED_DIFFERENCES[fixture];
    if (accepted) {
      const pycti = Object.fromEntries(Object.keys(accepted.pycti).map((key) => [key, key === 'calls' ? pinnedCalls(expected.calls, accepted.pycti.calls ?? []) : expected[key]]));
      expect(pycti, `pycti: ${accepted.reason}`).toEqual(accepted.pycti);
      expect({ ...actual, calls: pinnedCalls(actual.calls as unknown as Record<string, unknown>[], accepted.port.calls) }, `port: ${accepted.reason}`)
        .toEqual(accepted.port);
      return;
    }
    expected.calls.forEach((call: Record<string, unknown>, index: number) => {
      expect(actual.calls[index], `call ${index + 1}`).toEqual(call);
    });
    expect(actual.calls.length, 'number of calls').toEqual(expected.calls.length);
    expect({ items: actual.items, incompatible: actual.incompatible, bundle_error: actual.bundle_error, logged_errors: actual.logged_errors })
      .toEqual({ items: expected.items, incompatible: expected.incompatible, bundle_error: expected.bundle_error, logged_errors: expected.logged_errors });
  });
  it('should declare accepted differences of existing fixtures only', () => {
    expect(Object.keys(ACCEPTED_DIFFERENCES).filter((fixture) => !fixtures.includes(fixture)), 'stale accepted-differences.json entries').toEqual([]);
  });
  // Runs after the fixtures: the port's documents must be valid for the platform's schema, as in
  // process execution parses and validates them before any resolver
  it('should send only documents valid for the platform schema', () => {
    const schema = createSchema();
    expect(SEEN_DOCUMENTS.size).toBeGreaterThan(0);
    const invalid = [...SEEN_DOCUMENTS].flatMap((document) => validate(schema, parse(document)).map((error) => `${error.message}\n${document}`));
    expect(invalid).toEqual([]);
  });
  // Runs after the fixtures: every document of the port is sent by at least one fixture, so that
  // the schema validation above and the goldens cover all of them
  it('should send every GraphQL document of the port', () => {
    const documents = (readdirSync(PORT_DIR, { recursive: true }) as string[])
      .filter((path) => path.endsWith('.ts'))
      .flatMap((path) => [...readFileSync(join(PORT_DIR, path), 'utf-8').matchAll(/`(\s*(?:query|mutation)\b[^`]*)`/g)]
        .map((match) => ({ path, document: normalizeDocument(match[1]) })));
    expect(documents.length).toBeGreaterThan(0);
    // A document built at run time cannot be checked here
    expect(documents.filter(({ document }) => document.includes('${')), 'documents with an interpolation').toEqual([]);
    const seen = new Set([...SEEN_DOCUMENTS].map(normalizeDocument));
    const unseen = documents.filter(({ document }) => !seen.has(document));
    expect(unseen.filter(({ document }) => !(document in UNREACHABLE_DOCUMENTS)).map(({ path, document }) => `${path}: ${document}`)).toEqual([]);
    expect(Object.keys(UNREACHABLE_DOCUMENTS).filter((document) => !unseen.some((entry) => entry.document === document)), 'stale UNREACHABLE_DOCUMENTS').toEqual([]);
  });
  // Runs after the fixtures: the variables of every call are coerced as the platform does before
  // any resolver (a wrong enum value, a missing required field, a wrong scalar)
  it('should send only variables valid for the platform schema', () => {
    const schema = createSchema();
    expect(SEEN_CALLS.length).toBeGreaterThan(0);
    // A file is sent as a multipart part: give the Upload scalar what graphql-upload gives it
    const withUploads = (value: unknown): unknown => {
      if (value instanceof UploadFile) return new Upload();
      if (Array.isArray(value)) return value.map(withUploads);
      if (value !== null && typeof value === 'object') return Object.fromEntries(Object.entries(value).map(([key, item]) => [key, withUploads(item)]));
      return value;
    };
    // fixture -> refused variable -> first message
    const failing = new Map<string, Map<string, string>>();
    SEEN_CALLS.forEach(({ fixtureDir, document, variables }) => {
      const operation = parse(document).definitions.find((definition) => definition.kind === Kind.OPERATION_DEFINITION) as OperationDefinitionNode;
      const { errors } = getVariableValues(schema, operation.variableDefinitions ?? [], withUploads(variables) as Record<string, unknown>);
      const fixture = relative(FIXTURES_DIR, fixtureDir).split(sep).join('/');
      (errors ?? []).map((error) => error.message).filter((message) => !isMissingRequiredValue(fixture, message)).forEach((message) => {
        const refusals = failing.get(fixture) ?? new Map<string, string>();
        refusals.set(refusedVariable(message), refusals.get(refusedVariable(message)) ?? message);
        failing.set(fixture, refusals);
      });
    });
    const refused = [...failing.entries()].flatMap(([fixture, refusals]) => [...refusals.entries()]
      .filter(([variable]) => !(INVALID_VARIABLES[fixture]?.at ?? []).includes(variable))
      .map(([, message]) => `${fixture}: ${message}`));
    expect(refused).toEqual([]);
    const stale = Object.entries(INVALID_VARIABLES).flatMap(([fixture, { at }]) => at.filter((variable) => !failing.get(fixture)?.has(variable)).map((variable) => `${fixture}: ${variable}`));
    expect(stale, 'stale INVALID_VARIABLES').toEqual([]);
  });
});
