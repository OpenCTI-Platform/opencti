import { describe, expect, it } from 'vitest';
import { validate as uuidValidate } from 'uuid';
import { existsSync, readdirSync, readFileSync } from 'node:fs';
import { join, sep } from 'node:path';
import '../../../src/modules/index';
import createSchema from '../../../src/graphql/schema';
import { getVocabulariesCategories } from '../../../src/modules/vocabulary/vocabulary-utils';
import { createImportContext } from '../../../src/intake/stix-import/context';
import { eventBundle, transformBundle } from '../../../src/intake/stix-import/transform';
import { type ImportClient, ImportClientError, StixImportError, type StixObject, UploadFile } from '../../../src/intake/stix-import/types';
import { DryClient } from '../../../src/intake/dry-intake/dry-client';
import { answerOperation, describeOperation, standardIdOf } from '../../../src/intake/dry-intake/simulated-answers';
import { isSupportedStixType } from '../../../src/schema/identifier';
import { ACCEPTED_DIFFERENCES_FILE, DEFAULT_CALL, FIXTURES_DIR } from '../import-conformance/import-conformance-utils';

// The dry client must send the transformation down the same paths as the conformance client, or the
// dry bench measures a shorter transformation: on every fixture without a world of its own (reads
// or errors) and without an accepted difference, the same operations (root and nested operation)
// in the same order, and the same outcome per object, as pycti's golden.

const TRANSFORMATION_DIR = join(__dirname, '../../../src/intake/stix-import');
const readJson = (dir: string, file: string) => JSON.parse(readFileSync(join(dir, file), 'utf-8'));
const ACCEPTED_DIFFERENCES: Record<string, unknown> = JSON.parse(readFileSync(ACCEPTED_DIFFERENCES_FILE, 'utf-8'));
const allFixtures = (readdirSync(FIXTURES_DIR, { recursive: true }) as string[])
  .filter((path) => existsSync(join(FIXTURES_DIR, path, 'expected.json')))
  .map((path) => path.split(sep).join('/'))
  .sort();
const fixtures = allFixtures.filter((fixture) => !existsSync(join(FIXTURES_DIR, fixture, 'world.json')) && !(fixture in ACCEPTED_DIFFERENCES));

const transformWithDryClient = async (fixture: string, dryClient: DryClient) => {
  const dir = join(FIXTURES_DIR, fixture);
  const call = { ...DEFAULT_CALL, ...(existsSync(join(dir, 'call.json')) ? readJson(dir, 'call.json') : {}) };
  const input: StixObject = readJson(dir, 'input.json');
  const operations: { root: string; sub: string | null }[] = [];
  const refusals: string[] = [];
  const client: ImportClient = {
    query: async (document, variables) => {
      const { root, sub } = describeOperation(document);
      operations.push({ root, sub });
      try {
        return await dryClient.query(document, variables);
      } catch (error) {
        if (error instanceof ImportClientError) {
          refusals.push(error.message);
        }
        throw error;
      }
    },
  };
  const context = createImportContext(client, { error: () => {}, warn: () => {} }, { now: new Date(call.now) });
  let result: { items: { id: string; outcome: string }[]; incompatible: unknown[] } = { items: [], incompatible: [] };
  let bundleError: string | null = null;
  try {
    const bundle = call.message_type === 'event' ? { id: 'bundle--00000000-0000-0000-0000-000000000000', ...eventBundle(input) } : input;
    result = await transformBundle(context, bundle, call.message_type === 'event' ? true : call.update, call.types);
  } catch (error) {
    if (!(error instanceof StixImportError)) {
      throw error;
    }
    bundleError = error.name;
  }
  return { operations, items: result.items, incompatible: result.incompatible, bundle_error: bundleError, refusals };
};

const sameAsGolden = (fixture: string, actual: Awaited<ReturnType<typeof transformWithDryClient>>) => {
  const expected = readJson(join(FIXTURES_DIR, fixture), 'expected.json');
  expect(actual.operations).toEqual(expected.calls.map(({ root, sub }: { root: string; sub: string | null }) => ({ root, sub })));
  expect({ items: actual.items, incompatible: actual.incompatible, bundle_error: actual.bundle_error })
    .toEqual({ items: expected.items, incompatible: expected.incompatible, bundle_error: expected.bundle_error });
};

// Fixtures whose input the platform schema refuses where pycti's recorder accepts anything: the
// validate rung answers the GraphQL error the platform gives, and the transformation then takes
// pycti's error path, so they leave the golden on purpose. Each one is pinned to the refusal the
// schema gives (a new or another refusal fails the test below).
const SIMPLE_OBSERVABLE_ID = 'is not a valid STIX ID (type simple-observable not supported)';
const SCHEMA_REFUSALS: Record<string, string> = {
  'missing/attack-pattern-reference-without-source-name/attack-pattern.legacy': 'at .source_name: Expected value of non-null type "String!" not to be null',
  'missing/simple-observable-int-unicode-spaces/simple-observable.legacy': SIMPLE_OBSERVABLE_ID,
  'missing/simple-observable-unicode-digits/simple-observable.legacy': SIMPLE_OBSERVABLE_ID,
  'missing/vocabulary-value-dict/malware.legacy': 'String cannot represent a non string value: { a: 1 }',
  'ops/merge/sources-dict.ext': '"$stixObjectsIds" has invalid value: Expected value of type "String"',
  'sco/simple-observable/handwritten-as-number.legacy': SIMPLE_OBSERVABLE_ID,
  'sco/simple-observable/handwritten-ipv4-value.ext': SIMPLE_OBSERVABLE_ID,
  'sco/simple-observable/handwritten-ipv4-value.legacy': SIMPLE_OBSERVABLE_ID,
  'sdo/malware/handwritten-external-reference-external-id-zero.legacy': 'at .external_id: Expected value of type "String"',
  'variants-review/simple-observable-proto-key/simple-observable.legacy': SIMPLE_OBSERVABLE_ID,
};

describe('Dry intake client: same transformation paths as the conformance client', () => {
  it('should leave out only a few fixtures', () => {
    expect(fixtures.length).toBeGreaterThan(300);
    // A pinned refusal of a fixture that no longer runs would vanish from the check
    expect(Object.keys(SCHEMA_REFUSALS).filter((fixture) => !fixtures.includes(fixture))).toEqual([]);
  });
  it.each(fixtures)('%s', async (fixture) => {
    sameAsGolden(fixture, await transformWithDryClient(fixture, new DryClient({ vocabularyCategories: getVocabulariesCategories() })));
  });
  // The validate rung keeps the same paths: an id the dry client answers is one the schema accepts
  // when the transformation sends it back, and only a value the platform really refuses diverges
  describe('at the validate rung', () => {
    const schema = createSchema();
    it.each(fixtures)('%s', async (fixture) => {
      const actual = await transformWithDryClient(fixture, new DryClient({ vocabularyCategories: getVocabulariesCategories() }, schema));
      expect(actual.refusals.filter((message) => message.includes('00000000-0000-4000-8000-'))).toEqual([]);
      if (fixture in SCHEMA_REFUSALS) {
        expect(actual.refusals.length).toBeGreaterThan(0);
        actual.refusals.forEach((message) => expect(message).toContain(SCHEMA_REFUSALS[fixture]));
      } else {
        expect(actual.refusals).toEqual([]);
        sameAsGolden(fixture, actual);
      }
    });
  });
  // With the schema (the validate rung), a refused operation is a GraphQL error the transformation
  // handles as pycti does: no fixture may end in a native error
  it('should validate every fixture against the schema without a native error', async () => {
    const dryClient = new DryClient({ vocabularyCategories: getVocabulariesCategories() }, createSchema());
    for (const fixture of allFixtures) {
      await transformWithDryClient(fixture, dryClient);
    }
    expect(dryClient.operations).toBeGreaterThan(1000);
  });
  it('should refuse a document the schema does not validate with the GraphQL error the platform gives', async () => {
    const dryClient = new DryClient({}, createSchema());
    const refused = dryClient.query('query Unknown { unknownRootField { id } }', {});
    await expect(refused).rejects.toBeInstanceOf(ImportClientError);
    await expect(refused).rejects.toMatchObject({ code: 'GRAPHQL_VALIDATION_FAILED' });
  });
  // Only the path to a file is copied for the coercion: a file below a plain object is still
  // given to the Upload scalar as graphql-upload gives it, and the variables are left as they are
  it('should coerce a file nested in the variables as an upload, without touching the variables', async () => {
    const dryClient = new DryClient({}, createSchema());
    const document = 'mutation ExternalReferenceAdd($input: ExternalReferenceAddInput!) { externalReferenceAdd(input: $input) { id } }';
    const file = new UploadFile('report.pdf', Buffer.from('report'), 'application/pdf');
    const markings = [['marking']];
    const input = { source_name: 'source', url: 'https://example.com/report', files: [file], filesMarkings: markings };
    const variables = { input };
    await expect(dryClient.query(document, variables)).resolves.toBeDefined();
    expect(Object.keys(variables)).toEqual(['input']);
    expect(Object.keys(input)).toEqual(['source_name', 'url', 'files', 'filesMarkings']);
    expect(input.files).toEqual([file]);
    expect(input.files[0]).toBe(file);
    expect(input.filesMarkings).toBe(markings);
    expect(markings).toEqual([['marking']]);
    const refused = dryClient.query(document, { input: { ...input, files: [{ name: 'report.pdf' }] } });
    await expect(refused).rejects.toBeInstanceOf(ImportClientError);
    await expect(refused).rejects.toMatchObject({ code: 'BAD_USER_INPUT' });
  });
  // An observed-data sends the standard_id of the observables it creates in its objects: the dry
  // client answers it as the platform does, a STIX id of a supported type
  it('should answer the standard_id of a created element as a STIX id', async () => {
    const dryClient = new DryClient({});
    const document = 'mutation ObservableAdd($type: String!, $stix_id: StixId, $IPv4Addr: IPv4AddrAddInput) { stixCyberObservableAdd(type: $type, stix_id: $stix_id, IPv4Addr: $IPv4Addr) { id standard_id entity_type } }';
    const given = 'ipv4-addr--10000000-0000-4000-8000-000000000001';
    expect((await dryClient.query(document, { type: 'IPv4-Addr', stix_id: given, IPv4Addr: { value: '1.1.1.1' } })).stixCyberObservableAdd.standard_id).toEqual(given);
    const created = (await dryClient.query(document, { type: 'IPv4-Addr', IPv4Addr: { value: '1.1.1.2' } })).stixCyberObservableAdd;
    const relationship = (await dryClient.query('mutation R($input: StixCoreRelationshipAddInput!) { stixCoreRelationshipAdd(input: $input) { id standard_id } }', { input: { relationship_type: 'uses' } })).stixCoreRelationshipAdd;
    const attackPattern = (await dryClient.query('mutation A($input: AttackPatternAddInput!) { attackPatternAdd(input: $input) { id standard_id } }', { input: { name: 'a' } })).attackPatternAdd;
    // The STIX type, not the platform type, as the platform answers it (convertTypeToStixType)
    const file = (await dryClient.query('mutation F($type: String!, $StixFile: StixFileAddInput) { stixCyberObservableAdd(type: $type, StixFile: $StixFile) { id standard_id } }', { type: 'StixFile', StixFile: { name: 'a.exe' } })).stixCyberObservableAdd;
    const sighting = (await dryClient.query('mutation S($input: StixSightingRelationshipAddInput!) { stixSightingRelationshipAdd(input: $input) { id standard_id } }', { input: { fromId: 'a', toId: 'b' } })).stixSightingRelationshipAdd;
    const individual = (await dryClient.query('mutation I($input: IndividualAddInput!) { individualAdd(input: $input) { id standard_id } }', { input: { name: 'a' } })).individualAdd;
    const city = (await dryClient.query('mutation C($input: CityAddInput!) { cityAdd(input: $input) { id standard_id } }', { input: { name: 'a' } })).cityAdd;
    const threatActor = (await dryClient.query('mutation T($input: ThreatActorGroupAddInput!) { threatActorGroupAdd(input: $input) { id standard_id } }', { input: { name: 'a' } })).threatActorGroupAdd;
    const securityPlatform = (await dryClient.query('mutation P($input: SecurityPlatformAddInput!) { securityPlatformAdd(input: $input) { id standard_id } }', { input: { name: 'a' } })).securityPlatformAdd;
    const answered = [[created, 'ipv4-addr'], [relationship, 'relationship'], [attackPattern, 'attack-pattern'], [file, 'file'], [sighting, 'sighting'], [individual, 'identity'], [city, 'location'], [threatActor, 'threat-actor'], [securityPlatform, 'identity']];
    for (const [element, type] of answered) {
      const [stixType, uuid] = element.standard_id.split('--');
      expect(stixType).toEqual(type);
      expect(isSupportedStixType(stixType)).toBe(true);
      expect(uuidValidate(uuid)).toBe(true);
    }
  });
  // Every creation root the transformation sends, read from its sources: a supported STIX type
  it('should answer a supported STIX type for every creation root of the transformation', () => {
    const sources = (readdirSync(TRANSFORMATION_DIR, { recursive: true }) as string[]).filter((file) => file.endsWith('.ts')).map((file) => readFileSync(join(TRANSFORMATION_DIR, file), 'utf-8'));
    const roots = [...new Set(sources.flatMap((source) => [...source.matchAll(/\b([a-z][A-Za-z]+Add)\b/g)].map((match) => match[1])))]
      // Not a creation: a nested operation of an edit, answering the edited element
      .filter((root) => root !== 'restrictionOrganizationAdd')
      .sort();
    expect(roots.length).toBeGreaterThan(40);
    const relationships = ['relationAdd', 'stixCoreRelationshipAdd', 'stixRefRelationshipAdd'];
    const unsupported = roots.filter((root) => {
      let variables: Record<string, unknown> = { input: {} };
      if (relationships.includes(root)) {
        variables = { input: { relationship_type: 'uses' } };
      } else if (root === 'stixCyberObservableAdd') {
        variables = { type: 'IPv4-Addr' };
      }
      const operation = { op: 'mutation', name: null, root, sub: null, scalar: false };
      const answered = answerOperation(operation, variables, {}, () => 'id', standardIdOf);
      return !isSupportedStixType(answered.standard_id.split('--')[0]);
    });
    expect(unsupported).toEqual([]);
  });
});
