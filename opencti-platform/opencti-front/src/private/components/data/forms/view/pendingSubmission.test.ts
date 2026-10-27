import { describe, expect, it } from 'vitest';
import { createPendingCollector, PendingOption } from './pendingSubmission';
import { prepareFormSubmission } from './FormViewUtils';
import { FormSchemaDefinition } from '../Form.d';
import { PendingObjectData } from '../../../../../utils/hooks/useDeferredCreation';

const store = new Map<string, PendingObjectData>([
  ['__pending__:label', { entityType: 'Label', input: { value: 'new-label', color: '#ff0000' } }],
  ['__pending__:ref', { entityType: 'External-Reference', input: { source_name: 'src', url: 'https://example.com', files: [], embedded: [] } }],
]);
const getPending = (id: string) => store.get(id);

const option = (value: string, entityType: string, input: Record<string, unknown>): PendingOption => ({
  value,
  isPendingCreation: true,
  pendingInputData: { entityType, input },
});

describe('createPendingCollector.root', () => {
  it('keeps the legacy input as is, only with its local id', () => {
    const collector = createPendingCollector();
    const root = collector.root(option('__pending__:m', 'Malware', { name: 'M', confidence: 50 }));
    expect(root).toEqual({ id: '__pending__:m', entityType: 'Malware', input: { name: 'M', confidence: 50 } });
    expect(collector.files).toEqual([]);
    expect(collector.pooled()).toEqual([]);
  });

  it('moves the references out of the input into refs, pending labels and external references to the pool', () => {
    const collector = createPendingCollector(getPending);
    const root = collector.root(option('__pending__:m', 'Malware', {
      name: 'M',
      createdBy: 'author-1',
      objectMarking: ['marking-1'],
      objectLabel: ['label-1', '__pending__:label'],
      externalReferences: ['__pending__:ref'],
      killChainPhases: ['phase-1'],
    }));
    expect(root.input).toEqual({ name: 'M' });
    expect(root.refs).toEqual({
      createdBy: { existing: 'author-1' },
      objectMarking: [{ existing: 'marking-1' }],
      objectLabel: [{ existing: 'label-1' }, { pending: '__pending__:label' }],
      externalReferences: [{ pending: '__pending__:ref' }],
      killChainPhases: [{ existing: 'phase-1' }],
    });
    expect(collector.pooled()).toEqual([
      { id: '__pending__:label', entityType: 'Label', input: { value: 'new-label', color: '#ff0000' } },
      { id: '__pending__:ref', entityType: 'External-Reference', input: { source_name: 'src', url: 'https://example.com' } },
    ]);
  });

  it('pools a pending object referenced twice once', () => {
    const collector = createPendingCollector(getPending);
    collector.root(option('__pending__:a', 'Malware', { name: 'A', objectLabel: ['__pending__:label'] }));
    collector.root(option('__pending__:b', 'Malware', { name: 'B', objectLabel: ['__pending__:label'] }));
    expect(collector.pooled()).toHaveLength(1);
  });

  it('sends the files and markdown images of a pooled external reference as uploads too', () => {
    const pooledFile = new File(['p'], 'proof.pdf', { type: 'application/pdf' });
    const image = new File(['i'], 'shot.png', { type: 'image/png' });
    const withFiles = new Map(store);
    withFiles.set('__pending__:ref', { entityType: 'External-Reference', input: { source_name: 'src', files: [image, pooledFile], embedded: [true, false] } });
    const collector = createPendingCollector((id) => withFiles.get(id));
    collector.root(option('__pending__:m', 'Malware', { name: 'M', externalReferences: ['__pending__:ref'] }));
    expect(collector.files).toEqual([image, pooledFile]);
    expect(collector.pooled()).toEqual([{
      id: '__pending__:ref',
      entityType: 'External-Reference',
      input: { source_name: 'src' },
      files: [
        { name: 'shot.png', mime_type: 'image/png', uploadIndex: 0, embedded: true },
        { name: 'proof.pdf', mime_type: 'application/pdf', uploadIndex: 1 },
      ],
    }]);
  });

  it('never pools an unreferenced object', () => {
    const collector = createPendingCollector(getPending);
    collector.root(option('__pending__:m', 'Malware', { name: 'M' }));
    expect(collector.pooled()).toEqual([]);
  });

  it('extracts the files into uploads referenced by index', () => {
    const collector = createPendingCollector();
    const first = new File(['a'], 'a.txt', { type: 'text/plain' });
    const second = new File(['b'], 'b.bin');
    const root = collector.root(option('__pending__:m', 'Malware', { name: 'M', files: [first], embedded: [false] }));
    const other = collector.root(option('__pending__:n', 'Malware', { name: 'N', files: [second], embedded: [true] }));
    expect(collector.files).toEqual([first, second]);
    expect(root.files).toEqual([{ name: 'a.txt', mime_type: 'text/plain', uploadIndex: 0 }]);
    expect(other.files).toEqual([{ name: 'b.bin', mime_type: undefined, uploadIndex: 1, embedded: true }]);
    expect(root.input).toEqual({ name: 'M' });
  });

  it('extracts the files and markdown images an observable carries under its type key', () => {
    const collector = createPendingCollector();
    const image = new File(['i'], 'pasted.png', { type: 'image/png' });
    const attached = new File(['a'], 'a.txt', { type: 'text/plain' });
    const root = collector.root(option('__pending__:ip', 'IPv4-Addr', {
      type: 'IPv4-Addr',
      x_opencti_description: '![pasted](opencti-image://temp/00000000-0000-0000-0000-000000000001)',
      IPv4Addr: { value: '1.2.3.4', files: [image, attached], embedded: [true, false] },
    }));
    expect(collector.files).toEqual([image, attached]);
    expect(root.files).toEqual([
      { name: 'pasted.png', mime_type: 'image/png', uploadIndex: 0, embedded: true },
      { name: 'a.txt', mime_type: 'text/plain', uploadIndex: 1 },
    ]);
    expect(root.input).toEqual({
      type: 'IPv4-Addr',
      x_opencti_description: '![pasted](opencti-image://temp/00000000-0000-0000-0000-000000000001)',
      IPv4Addr: { value: '1.2.3.4' },
    });
  });

  it('sends the content of an Artifact once, given at the top level and under its type key', () => {
    const collector = createPendingCollector();
    const sample = new File(['x'], 'sample.bin');
    const root = collector.root(option('__pending__:a', 'Artifact', { type: 'Artifact', file: sample, Artifact: { file: sample, mime_type: 'x' } }));
    expect(collector.files).toEqual([sample]);
    expect(root.files).toEqual([{ name: 'sample.bin', mime_type: undefined, uploadIndex: 0 }]);
    expect(root.input).toEqual({ type: 'Artifact', Artifact: { mime_type: 'x' } });
  });
});

describe('prepareFormSubmission', () => {
  const field = (name: string, type: string) => ({
    id: name,
    name,
    label: name,
    type,
    attributeMapping: { entity: 'main_entity', attributeName: name },
  });
  const schema = {
    version: '2.0',
    mainEntityType: 'Malware',
    additionalEntities: [],
    relationships: [],
    fields: [field('name', 'text'), field('objectLabel', 'objectLabel'), field('externalReferences', 'externalReferences')],
  } as unknown as FormSchemaDefinition;
  type Values = Parameters<typeof prepareFormSubmission>[0];

  it('sends pending labels and external references of direct fields as pending refs with their pool', () => {
    const values = {
      name: 'Direct',
      objectLabel: [
        { label: 'existing-label', value: 'label-1' },
        { label: 'new-label', value: '__pending__:label' },
      ],
      externalReferences: [
        { value: 'ref-1' },
        { id: '__pending__:ref', value: '__pending__:ref' },
      ],
    };
    const { values: formatted, files } = prepareFormSubmission(values as unknown as Values, schema, getPending);
    expect(formatted.objectLabel).toEqual(['existing-label', { pending: '__pending__:label' }]);
    expect(formatted.externalReferences).toEqual(['ref-1', { pending: '__pending__:ref' }]);
    expect(formatted.pendingObjects).toHaveLength(2);
    expect(files).toEqual([]);
  });

  it('does not add a pool when nothing is pending', () => {
    const values = { name: 'Plain', objectLabel: [{ label: 'a', value: 'label-1' }] };
    const { values: formatted } = prepareFormSubmission(values as unknown as Values, schema, getPending);
    expect(formatted).not.toHaveProperty('pendingObjects');
    expect(formatted.objectLabel).toEqual(['a']);
  });

  it('returns the files of the lookup roots', () => {
    const lookupSchema = { ...schema, mainEntityLookup: true, mainEntityMultiple: false } as FormSchemaDefinition;
    const file = new File(['x'], 'evidence.txt', { type: 'text/plain' });
    const values = { mainEntityLookup: option('__pending__:m', 'Malware', { name: 'M', files: [file], embedded: [false] }) };
    const { values: formatted, files } = prepareFormSubmission(values as unknown as Values, lookupSchema, getPending);
    expect(files).toEqual([file]);
    expect(formatted.mainEntityLookupPending).toEqual([
      { id: '__pending__:m', entityType: 'Malware', input: { name: 'M' }, files: [{ name: 'evidence.txt', mime_type: 'text/plain', uploadIndex: 0 }] },
    ]);
  });
});
