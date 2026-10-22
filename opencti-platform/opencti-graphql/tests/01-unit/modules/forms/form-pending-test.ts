import { beforeEach, describe, expect, it, vi } from 'vitest';
import { Readable } from 'stream';
import '../../../../src/modules/index'; // registers the entity types and their attributes
import { internalLoadById } from '../../../../src/database/middleware-loader';
import {
  countPooledCopies,
  getPendingRoots,
  getPendingUploadCopies,
  materializePendingRoots,
  MAX_PENDING_POOL,
  MAX_PENDING_POOLED_BYTES,
  MAX_PENDING_REFS_PER_OBJECT,
  MAX_PENDING_REFS_TOTAL,
  MAX_PENDING_ROOTS,
  MAX_PENDING_UPLOAD_BYTES,
  readUploads,
  resolvePendingFieldRefs,
  validatePendingPayload,
  validatePendingRoots,
  withPendingExternalReferenceFiles,
  type PendingObject,
} from '../../../../src/modules/form/form-pending';
import type { AuthContext } from '../../../../src/types/user';
import type { FormSchemaDefinition } from '../../../../src/modules/form/form-types';
import { SYSTEM_USER } from '../../../../src/utils/access';

vi.mock('../../../../src/database/middleware-loader', () => ({
  internalLoadById: vi.fn(),
}));

const context = {} as AuthContext;
const user = SYSTEM_USER;
const malware = (extra: Partial<PendingObject> = {}): PendingObject => ({ entityType: 'Malware', input: { name: 'Pending' }, ...extra });
const label = (id: string): PendingObject => ({ id, entityType: 'Label', input: { value: 'new-label' } });
const extRef = (id: string): PendingObject => ({ id, entityType: 'External-Reference', input: { source_name: 'src', url: 'https://example.com' } });

describe('getPendingRoots', () => {
  it('should collect main and additional lookup pending arrays only', () => {
    const roots = getPendingRoots({
      mainEntityLookupPending: [malware()],
      additional_a_lookup_pending: [malware(), malware()],
      pendingObjects: [label('l1')],
      other: [malware()],
    });
    expect(roots).toHaveLength(3);
  });
});

describe('validatePendingPayload', () => {
  it('should accept the legacy payload without id, refs or files', () => {
    expect(() => validatePendingPayload({ mainEntityLookupPending: [malware()] }, 0)).not.toThrow();
  });

  it('should accept pending refs to pooled labels and external references', () => {
    const values = {
      mainEntityLookupPending: [malware({ refs: { objectLabel: [{ pending: 'l1' }, { existing: 'label-1' }], externalReferences: [{ pending: 'e1' }] } })],
      pendingObjects: [label('l1'), extRef('e1')],
    };
    expect(() => validatePendingPayload(values, 0)).not.toThrow();
  });

  it('should reject duplicate ids', () => {
    const values = { mainEntityLookupPending: [malware({ id: 'x' })], pendingObjects: [label('x')] };
    expect(() => validatePendingPayload(values, 0)).toThrow('Duplicate pending object id');
  });

  it('should reject a dangling pending ref', () => {
    const values = { mainEntityLookupPending: [malware({ refs: { objectLabel: [{ pending: 'nope' }] } })] };
    expect(() => validatePendingPayload(values, 0)).toThrow('Pending ref not found in submission');
  });

  it('should reject a pending author', () => {
    const values = {
      mainEntityLookupPending: [malware({ refs: { createdBy: { pending: 'org' } } })],
      additional_a_lookup_pending: [{ id: 'org', entityType: 'Organization', input: { name: 'Org' } }],
    };
    expect(() => validatePendingPayload(values, 0)).toThrow('Pending ref cannot target this entity type');
  });

  it('should reject a pending ref of the wrong kind', () => {
    const values = { mainEntityLookupPending: [malware({ refs: { objectLabel: [{ pending: 'e1' }] } })], pendingObjects: [extRef('e1')] };
    expect(() => validatePendingPayload(values, 0)).toThrow('Pending ref cannot target this entity type');
  });

  it('should reject a pooled object that is not a label or an external reference', () => {
    const values = { pendingObjects: [{ id: 'm1', entityType: 'Malware', input: {} }] };
    expect(() => validatePendingPayload(values, 0)).toThrow('Only labels and external references can be pooled');
  });

  it('should reject an unsupported ref key', () => {
    const values = { mainEntityLookupPending: [malware({ refs: { objects: [{ existing: 'a' }] } as any })] };
    expect(() => validatePendingPayload(values, 0)).toThrow('Unsupported pending ref');
  });

  it('should reject a file pointing outside the uploads', () => {
    const values = { mainEntityLookupPending: [malware({ files: [{ name: 'a.txt', uploadIndex: 1 }] })] };
    expect(() => validatePendingPayload(values, 1)).toThrow('Pending file refers to a missing upload');
    const both = { mainEntityLookupPending: [malware({ files: [{ name: 'a.txt', uploadIndex: 0 }, { name: 'b.txt', uploadIndex: 1 }] })] };
    expect(() => validatePendingPayload(both, 2)).not.toThrow();
  });

  it('should reject an upload that no object references', () => {
    const values = { mainEntityLookupPending: [malware({ files: [{ name: 'a.txt', uploadIndex: 1 }] })] };
    expect(() => validatePendingPayload(values, 2)).toThrow('An upload is not referenced by any object created in the form');
    expect(() => validatePendingPayload({}, 1)).toThrow('An upload is not referenced');
    // an upload of a pooled object is referenced once an object of the form uses the pooled object
    const pooled = { pendingObjects: [{ ...extRef('e1'), files: [{ name: 'a.txt', uploadIndex: 0 }] }] };
    expect(() => validatePendingPayload(pooled, 1)).toThrow('An upload is not referenced by any object created in the form');
    const used = { ...pooled, mainEntityLookupPending: [malware({ refs: { externalReferences: [{ pending: 'e1' }] } })] };
    expect(() => validatePendingPayload(used, 1)).not.toThrow();
  });

  it('should reject files on a pooled label', () => {
    const values = {
      mainEntityLookupPending: [malware({ refs: { objectLabel: [{ pending: 'l1' }] } })],
      pendingObjects: [{ ...label('l1'), files: [{ name: 'a.txt', uploadIndex: 0 }] }],
    };
    expect(() => validatePendingPayload(values, 1)).toThrow('Files cannot be attached to a label created in a form');
  });

  it('should count the copies of each upload put in the bundle', () => {
    const values = {
      mainEntityLookupPending: [malware({
        files: [{ name: 'a', uploadIndex: 2 }, { name: 'b', uploadIndex: 0 }],
        refs: { externalReferences: [{ pending: 'e1' }] },
      })],
      additional_a_lookup_pending: [malware({ files: [{ name: 'c', uploadIndex: 2 }], refs: { externalReferences: [{ pending: 'e1' }] } })],
      // a direct field of the form uses the pooled external reference too
      externalReferences: [{ pending: 'e1' }, 'existing-ref'],
      pendingObjects: [{ ...extRef('e1'), files: [{ name: 'd', uploadIndex: 1 }] }, { ...extRef('e2'), files: [{ name: 'e', uploadIndex: 3 }] }],
    };
    expect(countPooledCopies(values)).toEqual(new Map([['e1', 3]]));
    // the files of a pooled object are copied with it; an unused pooled object is never put in the bundle
    expect(getPendingUploadCopies(values)).toEqual(new Map([[0, 1], [1, 3], [2, 2]]));
    // the same upload listed twice on an object is copied twice
    expect(getPendingUploadCopies({ mainEntityLookupPending: [malware({ files: [{ name: 'a', uploadIndex: 0 }, { name: 'a', uploadIndex: 0 }] })] }))
      .toEqual(new Map([[0, 2]]));
    expect(getPendingUploadCopies({})).toEqual(new Map());
  });

  it('should cap the size of the pooled objects once copied on the objects that use them', () => {
    const big = { id: 'e1', entityType: 'External-Reference', input: { source_name: 's', description: 'x'.repeat(MAX_PENDING_POOLED_BYTES / 4) } };
    const usedBy = (count: number) => ({ externalReferences: Array.from({ length: count }, () => ({ pending: 'e1' })), pendingObjects: [big] });
    expect(() => validatePendingPayload(usedBy(3), 0)).not.toThrow();
    expect(() => validatePendingPayload(usedBy(4), 0)).toThrow('The labels and external references created in the form are too large');
  });

  it('should cap the number of roots, of pooled objects and of references of an object', () => {
    const many = (count: number, build: (index: number) => PendingObject) => Array.from({ length: count }, (_, index) => build(index));
    expect(() => validatePendingPayload({ mainEntityLookupPending: many(MAX_PENDING_ROOTS, () => malware()) }, 0)).not.toThrow();
    expect(() => validatePendingPayload({ mainEntityLookupPending: many(MAX_PENDING_ROOTS + 1, () => malware()) }, 0)).toThrow('Too many objects');
    expect(() => validatePendingPayload({ pendingObjects: many(MAX_PENDING_POOL, (i) => label(`l${i}`)) }, 0)).not.toThrow();
    expect(() => validatePendingPayload({ pendingObjects: many(MAX_PENDING_POOL + 1, (i) => label(`l${i}`)) }, 0)).toThrow('Too many labels and external references');
    const refs = (count: number) => ({ objectMarking: Array.from({ length: count }, (_, i) => ({ existing: `m${i}` })) });
    expect(() => validatePendingPayload({ mainEntityLookupPending: [malware({ refs: refs(MAX_PENDING_REFS_PER_OBJECT) })] }, 0)).not.toThrow();
    expect(() => validatePendingPayload({ mainEntityLookupPending: [malware({ refs: refs(MAX_PENDING_REFS_PER_OBJECT + 1) })] }, 0)).toThrow('Too many references');
    // the references are counted all kinds together
    const mixed = { objectMarking: [{ existing: 'm' }], objectLabel: Array.from({ length: MAX_PENDING_REFS_PER_OBJECT }, () => ({ existing: 'l' })) };
    expect(() => validatePendingPayload({ mainEntityLookupPending: [malware({ refs: mixed })] }, 0)).toThrow('Too many references');
  });
});

describe('validatePendingPayload - shapes', () => {
  const check = (values: Record<string, any>) => () => validatePendingPayload(values, 0);

  it('should ignore an absent or null field', () => {
    expect(check({ mainEntityLookupPending: null, pendingObjects: null })).not.toThrow();
    expect(check({ mainEntityLookupPending: [], additional_a_lookup_pending: undefined })).not.toThrow();
    // a single object is accepted like a list of one
    expect(check({ mainEntityLookupPending: malware() })).not.toThrow();
  });

  it.each([
    ['a null root', { mainEntityLookupPending: [null] }],
    ['a string root', { mainEntityLookupPending: ['Malware'] }],
    ['a list as a root', { mainEntityLookupPending: [[malware()]] }],
    ['a root field that is not an object nor a list', { mainEntityLookupPending: 'Malware' }],
    ['a numeric root field', { additional_a_lookup_pending: 12 }],
    ['a pool that is not a list', { pendingObjects: label('l1') }],
    ['a null pooled object', { pendingObjects: [null] }],
    ['a missing entityType', { mainEntityLookupPending: [{ input: { name: 'M' } }] }],
    ['an empty entityType', { mainEntityLookupPending: [{ entityType: '', input: { name: 'M' } }] }],
    ['a non string entityType', { mainEntityLookupPending: [{ entityType: 12, input: { name: 'M' } }] }],
    ['a missing input', { mainEntityLookupPending: [{ entityType: 'Malware' }] }],
    ['a null input', { mainEntityLookupPending: [{ entityType: 'Malware', input: null }] }],
    ['a list input', { mainEntityLookupPending: [{ entityType: 'Malware', input: [] }] }],
    ['a string input', { mainEntityLookupPending: [{ entityType: 'Malware', input: 'name' }] }],
    ['a non string id', { mainEntityLookupPending: [malware({ id: 12 as any })] }],
    ['an empty id', { mainEntityLookupPending: [malware({ id: '' })] }],
    ['refs that are a list', { mainEntityLookupPending: [malware({ refs: [] as any })] }],
    ['files that are not a list', { mainEntityLookupPending: [malware({ files: 'a.txt' as any })] }],
    ['a null file', { mainEntityLookupPending: [malware({ files: [null as any] })] }],
    ['a file with a non string name', { mainEntityLookupPending: [malware({ files: [{ name: 12, uploadIndex: 0 } as any] })] }],
    ['a file with a non boolean embedded flag', { mainEntityLookupPending: [malware({ files: [{ name: 'a', uploadIndex: 0, embedded: 'yes' } as any] })] }],
  ])('should throw a functional error, not a type error, on %s', (_name, values) => {
    expect(check(values)).toThrow(/functional|must be|requires|Invalid|Duplicate/i);
    try {
      validatePendingPayload(values, 0);
    } catch (error: any) {
      expect(error).not.toBeInstanceOf(TypeError);
      expect(error.extensions?.code).toBe('FUNCTIONAL_ERROR');
    }
  });

  it.each([
    ['a string ref', 'label-1'],
    ['an empty ref', {}],
    ['a ref without a string id', { existing: 12 }],
    ['an empty id', { existing: '' }],
    ['a ref with two kinds', { existing: 'a', pending: 'b' }],
    ['a ref of an unknown kind', { other: 'a' }],
  ])('should reject %s in the refs', (_name, ref) => {
    const values = { mainEntityLookupPending: [malware({ refs: { objectMarking: [ref] } as any })] };
    expect(check(values)).toThrow('Invalid pending ref');
    expect(check({ mainEntityLookupPending: [malware({ refs: { objectMarking: ref } as any })] })).toThrow();
  });

  it('should reject a null ref in a list of refs and ignore a null list of refs', () => {
    expect(check({ mainEntityLookupPending: [malware({ refs: { objectMarking: [null] } as any })] })).toThrow('Invalid pending ref');
    expect(check({ mainEntityLookupPending: [malware({ refs: { objectMarking: null } as any })] })).not.toThrow();
  });

  it('should reject a pooled label without a value and a pooled external reference without a source name', () => {
    const noValue = { pendingObjects: [{ id: 'l1', entityType: 'Label', input: {} }] };
    expect(check(noValue)).toThrow('A pooled pending object lacks a required attribute');
    expect(check({ pendingObjects: [{ id: 'l1', entityType: 'Label', input: { value: '' } }] })).toThrow('lacks a required attribute');
    expect(check({ pendingObjects: [{ id: 'l1', entityType: 'Label', input: { value: 12 } }] })).toThrow('lacks a required attribute');
    expect(check({ pendingObjects: [{ id: 'e1', entityType: 'External-Reference', input: { url: 'https://example.com' } }] })).toThrow('lacks a required attribute');
  });

  // Options of the creation dialogs, not attributes: the indicator dialog always sends createObservables
  it.each(['createObservables', 'createIndicator'])('should ignore the dialog option %s when it is off and name it when it is on', async (field) => {
    const off = malware({ input: { name: 'M', [field]: false } });
    expect(check({ mainEntityLookupPending: [off] })).not.toThrow();
    const [entity] = await materializePendingRoots(context, user, [off], {}, []) as any[];
    expect(entity[field]).toBeUndefined();
    const on = { mainEntityLookupPending: [malware({ input: { name: 'M', [field]: true } })] };
    expect(check(on)).toThrow(`This option is not supported when creating an object in a form: ${field}`);
  });

  it('should name the field in the unsupported field and unknown attribute errors', async () => {
    expect(check({ mainEntityLookupPending: [malware({ input: { name: 'M', caseTemplates: ['t'] } })] })).toThrow('creating an object in a form: caseTemplates');
    await expect(materializePendingRoots(context, user, [malware({ input: { name: 'M', not_an_attribute: 'x' } })], {}, []))
      .rejects.toThrow('This attribute cannot be set when creating an object in a form: not_an_attribute');
  });

  it.each(['objects', 'caseTemplates', 'content_mapping', 'authorized_members', 'customFieldValues', 'objectOrganization'])('should reject the filled input field %s', (field) => {
    const values = { mainEntityLookupPending: [malware({ input: { name: 'M', [field]: [{ id: 'x' }] } })] };
    expect(check(values)).toThrow('This field is not supported when creating an object in a form');
    // empty values are what the dialogs send when nothing is filled
    for (const empty of [[], '', null, undefined]) {
      expect(check({ mainEntityLookupPending: [malware({ input: { name: 'M', [field]: empty } })] })).not.toThrow();
    }
  });

  it('should accept the assignees and participants as refs or as ids left in the input', () => {
    const refs = { objectAssignee: [{ existing: 'user-1' }], objectParticipant: { existing: 'user-2' } };
    expect(check({ mainEntityLookupPending: [malware({ refs })] })).not.toThrow();
    const input = { name: 'M', objectAssignee: ['user-1'], objectParticipant: ['user-2'] };
    expect(check({ mainEntityLookupPending: [malware({ input })] })).not.toThrow();
    expect(check({ mainEntityLookupPending: [malware({ input: { name: 'M', objectAssignee: [{ value: 'user-1' }] } })] })).toThrow('must contain the ids of existing objects');
    expect(check({ mainEntityLookupPending: [malware({ input: { name: 'M', objectAssignee: [12] } })] })).toThrow('must contain the ids');
  });

  it('should reject the organizations an object is shared with, in the input and in the refs', () => {
    const message = 'This field is not supported when creating an object in a form';
    expect(check({ mainEntityLookupPending: [malware({ input: { name: 'M', objectOrganization: ['org-1'] } })] })).toThrow(message);
    expect(check({ mainEntityLookupPending: [malware({ refs: { objectOrganization: [{ existing: 'org-1' }] } as any })] })).toThrow(message);
    expect(check({ mainEntityLookupPending: [malware({ refs: { objectOrganization: { existing: 'org-1' } } as any })] })).toThrow(message);
    expect(check({ mainEntityLookupPending: [malware({ refs: { objectOrganization: { pending: 'l1' } } as any })], pendingObjects: [label('l1')] })).toThrow(message);
    // empty values are what the dialogs send when nothing is filled
    expect(check({ mainEntityLookupPending: [malware({ input: { name: 'M', objectOrganization: [] } })] })).not.toThrow();
  });

  it('should cap the references of the whole submission', () => {
    const marking = (count: number) => ({ objectMarking: Array.from({ length: count }, (_, i) => ({ existing: `m${i}` })) });
    const roots = (count: number, refs: number) => Array.from({ length: count }, () => malware({ refs: marking(refs) }));
    const perRoot = MAX_PENDING_REFS_PER_OBJECT;
    expect(check({ mainEntityLookupPending: roots(MAX_PENDING_REFS_TOTAL / perRoot, perRoot) })).not.toThrow();
    expect(check({ mainEntityLookupPending: roots(MAX_PENDING_REFS_TOTAL / perRoot + 1, perRoot) })).toThrow('Too many references in the objects created in the form');
    // spread over the roots of the main and additional fields, with the existing-only references of the input
    const input = { name: 'M', objectAssignee: Array.from({ length: 50 }, (_, i) => `u${i}`) };
    const many = Array.from({ length: MAX_PENDING_REFS_TOTAL / 50 + 1 }, () => malware({ input }));
    expect(check({ mainEntityLookupPending: many.slice(0, 10), additional_a_lookup_pending: many.slice(10) })).toThrow('Too many references in the objects');
  });

  it('should reject a pending ref for the existing-only references and several authors', () => {
    const pooled = { pendingObjects: [label('l1')] };
    for (const key of ['objectAssignee', 'objectParticipant', 'objectMarking', 'killChainPhases', 'createdBy']) {
      const values = { mainEntityLookupPending: [malware({ refs: { [key]: [{ pending: 'l1' }] } as any })], ...pooled };
      expect(check(values)).toThrow('Pending ref cannot target this entity type');
    }
    const authors = { createdBy: [{ existing: 'a' }, { existing: 'b' }] } as any;
    expect(check({ mainEntityLookupPending: [malware({ refs: authors })] })).toThrow('An object has a single author');
  });
});

describe('validatePendingRoots', () => {
  const schema = (extra: Partial<FormSchemaDefinition> = {}) => ({ version: '1', mainEntityType: 'Malware', mainEntityLookup: true, fields: [], ...extra }) as FormSchemaDefinition;
  const root = (entityType: string) => ({ entityType, input: { name: 'Pending' } });
  const additional = (extra: Record<string, any> = {}) => ({ id: 'a', label: 'A', entityType: 'Organization', multiple: true, lookup: true, parseFieldMapping: 'name', ...extra });

  it('should accept the legitimate main and additional roots', () => {
    const values = { mainEntityLookupPending: [root('Malware')], additional_a_lookup_pending: [root('Organization'), root('Organization')] };
    expect(() => validatePendingRoots(schema({ additionalEntities: [additional()] }), values)).not.toThrow();
    expect(() => validatePendingRoots(schema(), {})).not.toThrow();
  });

  it('should accept a subtype of the field type', () => {
    expect(() => validatePendingRoots(schema({ mainEntityType: 'Identity' }), { mainEntityLookupPending: [root('Organization')] })).not.toThrow();
    expect(() => validatePendingRoots(schema({ mainEntityType: 'Threat-Actor' }), { mainEntityLookupPending: [root('Threat-Actor-Group')] })).not.toThrow();
    expect(() => validatePendingRoots(schema({ mainEntityType: 'Stix-Cyber-Observable' }), { mainEntityLookupPending: [root('IPv4-Addr')] })).not.toThrow();
    expect(() => validatePendingRoots(schema({ additionalEntities: [additional({ entityType: 'Identity' })] }), { additional_a_lookup_pending: [root('Individual')] })).not.toThrow();
  });

  it('should reject a main lookup that is not a lookup or disables the creation', () => {
    const values = { mainEntityLookupPending: [root('Malware')] };
    expect(() => validatePendingRoots(schema({ mainEntityLookup: false }), values)).toThrow('not an entity lookup');
    expect(() => validatePendingRoots(schema({ mainEntityDisableCreation: true }), values)).toThrow('only existing ones can be selected');
  });

  it('should reject a root whose type is not the field type nor one of its subtypes', () => {
    expect(() => validatePendingRoots(schema(), { mainEntityLookupPending: [root('Report')] })).toThrow('cannot create an object of this type');
    expect(() => validatePendingRoots(schema(), { mainEntityLookupPending: [root('Malware'), root('Tool')] })).toThrow('cannot create an object of this type');
    const values = { additional_a_lookup_pending: [root('Malware')] };
    expect(() => validatePendingRoots(schema({ additionalEntities: [additional()] }), values)).toThrow('cannot create an object of this type');
  });

  it.each(['Label', 'User', 'uses', 'Marking-Definition'])('should reject the non creatable type %s even when the form type is that type', (type) => {
    expect(() => validatePendingRoots(schema({ mainEntityType: type }), { mainEntityLookupPending: [root(type)] })).toThrow('cannot create an object of this type');
  });

  it.each(['Identity', 'Container', 'Stix-Domain-Object'])('should reject the abstract type %s', (type) => {
    expect(() => validatePendingRoots(schema({ mainEntityType: type }), { mainEntityLookupPending: [root(type)] })).toThrow('cannot create an object of this type');
  });

  it('should reject an unknown additional entity or an unknown pending field', () => {
    expect(() => validatePendingRoots(schema(), { additional_ghost_lookup_pending: [root('Organization')] })).toThrow('Unknown field');
    expect(() => validatePendingRoots(schema(), { other_lookup_pending: [root('Malware')] })).toThrow('Unknown field');
    expect(() => validatePendingRoots(schema(), { additional_ghost_lookup_pending: [] })).not.toThrow();
  });

  it('should reject an additional entity that is not a lookup or disables the creation', () => {
    const values = { additional_a_lookup_pending: [root('Organization')] };
    expect(() => validatePendingRoots(schema({ additionalEntities: [additional({ lookup: false })] }), values)).toThrow('not an entity lookup');
    expect(() => validatePendingRoots(schema({ additionalEntities: [additional({ disableCreation: true })] }), values)).toThrow('only existing ones can be selected');
  });

  it('should accept a single object in a non multiple field counting the existing ones', () => {
    const single = schema({ mainEntityMultiple: false, additionalEntities: [additional({ multiple: false })] });
    expect(() => validatePendingRoots(single, { mainEntityLookupPending: [root('Malware')], mainEntityLookup: '' })).not.toThrow();
    expect(() => validatePendingRoots(single, { mainEntityLookupPending: [root('Malware'), root('Malware')] })).toThrow('single object');
    expect(() => validatePendingRoots(single, { mainEntityLookupPending: [root('Malware')], mainEntityLookup: 'id-1' })).toThrow('single object');
    expect(() => validatePendingRoots(single, { mainEntityLookupPending: [root('Malware')], mainEntityLookup: [] })).not.toThrow();
    const values = { additional_a_lookup_pending: [root('Organization')], additional_a_lookup: ['id-1'] };
    expect(() => validatePendingRoots(single, values)).toThrow('single object');
  });

  it('should accept several objects in a multiple field', () => {
    const multiple = schema({ mainEntityMultiple: true });
    expect(() => validatePendingRoots(multiple, { mainEntityLookupPending: [root('Malware'), root('Malware')], mainEntityLookup: ['id-1'] })).not.toThrow();
  });
});

describe('materializePendingRoots', () => {
  beforeEach(() => {
    vi.mocked(internalLoadById).mockReset();
  });

  it('should copy scalars and convert observable hashes to the store format', async () => {
    const roots: PendingObject[] = [{
      entityType: 'StixFile',
      input: { type: 'StixFile', StixFile: { name: 'a.exe', size: 12, hashes: [{ algorithm: 'SHA-256', hash: 'abc' }, { algorithm: 'MD5', hash: '' }] } },
    }];
    const [entity] = await materializePendingRoots(context, user, roots, {}, []) as any[];
    expect(entity.name).toBe('a.exe');
    expect(entity.size).toBe(12);
    expect(entity.hashes).toEqual({ 'SHA-256': 'abc' });
  });

  it('should copy the real attributes of each entity type', async () => {
    const roots: PendingObject[] = [
      { entityType: 'Intrusion-Set', input: { name: 'IS', aliases: ['a', 'b'], goals: ['g'], confidence: 80, description: 'd' } },
      { entityType: 'Attack-Pattern', input: { name: 'AP', x_mitre_id: 'T1' } },
      { entityType: 'Individual', input: { name: 'I', x_opencti_aliases: ['x'], contact_information: 'c' } },
      { entityType: 'Channel', input: { name: 'C', channel_types: ['t'] } },
      { entityType: 'IPv4-Addr', input: { type: 'IPv4-Addr', IPv4Addr: { value: '1.2.3.4' }, x_opencti_score: 10 } },
    ];
    const [intrusionSet, attackPattern, individual, channel, ip] = await materializePendingRoots(context, user, roots, {}, []) as any[];
    expect(intrusionSet).toEqual({ entity_type: 'Intrusion-Set', name: 'IS', aliases: ['a', 'b'], goals: ['g'], confidence: 80, description: 'd' });
    expect(attackPattern).toEqual({ entity_type: 'Attack-Pattern', name: 'AP', x_mitre_id: 'T1' });
    expect(individual).toEqual({ entity_type: 'Individual', name: 'I', x_opencti_aliases: ['x'], contact_information: 'c' });
    expect(channel).toEqual({ entity_type: 'Channel', name: 'C', channel_types: ['t'] });
    expect(ip).toEqual({ entity_type: 'IPv4-Addr', value: '1.2.3.4', name: '1.2.3.4', x_opencti_score: 10 });
  });

  it.each([
    'entity_type', 'standard_id', 'internal_id', 'id', 'x_opencti_stix_ids', 'creator_id', 'created_at', 'updated_at', 'stix_id',
    'restricted_members', 'parent_types', 'base_type', 'x_opencti_graph_data',
  ])('should reject the attribute %s that a user cannot set', async (key) => {
    const root = malware({ input: { name: 'M', [key]: key === 'restricted_members' ? 'x' : 'Report' } });
    await expect(materializePendingRoots(context, user, [root], {}, []))
      .rejects.toThrow('This attribute cannot be set when creating an object in a form');
  });

  it('should reject an attribute of an observable that is not one of its attributes', async () => {
    const input = { type: 'IPv4-Addr', IPv4Addr: { value: '1.2.3.4', entity_type: 'Malware' } };
    await expect(materializePendingRoots(context, user, [{ entityType: 'IPv4-Addr', input }], {}, []))
      .rejects.toThrow('This attribute cannot be set');
  });

  it('should drop the workflow status, the references of the type and the empty unknown keys', async () => {
    const input = { name: 'M', x_opencti_workflow_id: 'status-id', unknown_empty: '', unknown_null: null, unknown_list: [] };
    const [entity] = await materializePendingRoots(context, user, [malware({ input })], {}, []) as any[];
    expect(entity).toEqual({ entity_type: 'Malware', name: 'M' });
    const file = { entityType: 'StixFile', input: { type: 'StixFile', StixFile: { name: 'a.exe', obsContent: 'artifact-id' } } };
    expect(await materializePendingRoots(context, user, [file], {}, [])).toEqual([{ entity_type: 'StixFile', name: 'a.exe' }]);
  });

  it('should resolve the existing assignees and participants of refs and of the input', async () => {
    vi.mocked(internalLoadById).mockImplementation(async (_c, _u, id) => ({
      'user-1': { internal_id: 'user-1', standard_id: 'user--1', entity_type: 'User' },
      'user-2': { internal_id: 'user-2', standard_id: 'user--2', entity_type: 'User' },
    } as any)[id as string]);
    const root = malware({
      input: { name: 'M', objectParticipant: ['user-2'] },
      refs: { objectAssignee: [{ existing: 'user-1' }] },
    });
    const [entity] = await materializePendingRoots(context, user, [root], {}, []) as any[];
    expect(entity.objectOrganization).toBeUndefined();
    expect(entity.objectAssignee).toEqual([{ internal_id: 'user-1', standard_id: 'user--1' }]);
    expect(entity.objectParticipant).toEqual([{ internal_id: 'user-2', standard_id: 'user--2' }]);
    // the refs win over the ids left in the input
    const both = malware({ input: { name: 'M', objectAssignee: ['user-2'] }, refs: { objectAssignee: [{ existing: 'user-1' }] } });
    const [other] = await materializePendingRoots(context, user, [both], {}, []) as any[];
    expect(other.objectAssignee).toEqual([{ internal_id: 'user-1', standard_id: 'user--1' }]);
  });

  it('should load each existing reference once per call, even when many objects share it', async () => {
    vi.mocked(internalLoadById).mockImplementation(async (_c, _u, id) => ({
      'marking-1': { internal_id: 'marking-1', standard_id: 'marking-definition--1', entity_type: 'Marking-Definition' },
      'label-1': { internal_id: 'label-1', value: 'existing-label', entity_type: 'Label' },
    } as any)[id as string]);
    const refs = { objectMarking: [{ existing: 'marking-1' }, { existing: 'marking-1' }], objectLabel: [{ existing: 'label-1' }] };
    const roots = [malware({ refs }), malware({ refs }), malware({ refs })];
    const entities = await materializePendingRoots(context, user, roots, {}, []) as any[];
    expect(vi.mocked(internalLoadById)).toHaveBeenCalledTimes(2);
    expect(entities).toHaveLength(3);
    expect(entities[2].objectMarking).toHaveLength(2);
    // the memo does not outlive the call and does not hide a type mismatch
    await materializePendingRoots(context, user, roots, {}, []);
    expect(vi.mocked(internalLoadById)).toHaveBeenCalledTimes(4);
    await expect(materializePendingRoots(context, user, [malware({ refs: { objectLabel: [{ existing: 'marking-1' }] } })], {}, []))
      .rejects.toThrow('Pending ref does not target an accessible entity of the expected type');
  });

  it('should give each root its own copy of a pooled object shared by two roots', async () => {
    const roots = [malware({ input: { name: 'A' }, refs: { objectLabel: [{ pending: 'l1' }], externalReferences: [{ pending: 'e1' }] } }),
      malware({ input: { name: 'B' }, refs: { objectLabel: [{ pending: 'l1' }], externalReferences: [{ pending: 'e1' }] } })];
    const values = { mainEntityLookupPending: roots, pendingObjects: [label('l1'), extRef('e1')] };
    expect(() => validatePendingPayload(values, 0)).not.toThrow();
    const [first, second] = await materializePendingRoots(context, user, roots, values, []) as any[];
    expect(first.objectLabel).toEqual([{ value: 'new-label' }]);
    expect(second.objectLabel).toEqual([{ value: 'new-label' }]);
    expect(first.externalReferences).toEqual(second.externalReferences);
    expect(first.externalReferences[0]).not.toBe(second.externalReferences[0]);
  });

  it('should reject every kind of existing reference that points to the wrong type', async () => {
    const wrongType = { malware: { internal_id: 'x', standard_id: 'malware--x', entity_type: 'Malware' } };
    vi.mocked(internalLoadById).mockResolvedValue(wrongType.malware as any);
    for (const key of ['createdBy', 'objectMarking', 'objectLabel', 'externalReferences', 'killChainPhases', 'objectAssignee', 'objectParticipant']) {
      await expect(materializePendingRoots(context, user, [malware({ refs: { [key]: [{ existing: 'x' }] } as any })], {}, []))
        .rejects.toThrow('Pending ref does not target an accessible entity of the expected type');
    }
    // an existing kill chain phase and external reference of the right type are accepted
    vi.mocked(internalLoadById).mockImplementation(async (_c, _u, id) => ({
      'kc-1': { internal_id: 'kc-1', kill_chain_name: 'mitre', phase_name: 'execution', entity_type: 'Kill-Chain-Phase' },
      'ext-1': { internal_id: 'ext-1', source_name: 'src', entity_type: 'External-Reference' },
    } as any)[id as string]);
    const refs = { killChainPhases: [{ existing: 'kc-1' }], externalReferences: [{ existing: 'ext-1' }] };
    const [entity] = await materializePendingRoots(context, user, [malware({ refs })], {}, []) as any[];
    expect(entity.killChainPhases).toHaveLength(1);
    expect(entity.externalReferences).toHaveLength(1);
  });

  it('should reject an assignee or a participant of the wrong type', async () => {
    vi.mocked(internalLoadById).mockResolvedValue({ internal_id: 'x', standard_id: 'identity--x', entity_type: 'Individual' } as any);
    for (const key of ['objectAssignee', 'objectParticipant']) {
      await expect(materializePendingRoots(context, user, [malware({ refs: { [key]: [{ existing: 'x' }] } as any })], {}, []))
        .rejects.toThrow('Pending ref does not target an accessible entity of the expected type');
    }
  });

  it('should resolve existing and pending refs', async () => {
    vi.mocked(internalLoadById).mockImplementation(async (_c, _u, id) => ({
      'identity-1': { internal_id: 'identity-1', standard_id: 'identity--1', entity_type: 'Individual' },
      'marking-1': { internal_id: 'marking-1', standard_id: 'marking-definition--1', entity_type: 'Marking-Definition' },
      'label-1': { internal_id: 'label-1', value: 'existing-label', entity_type: 'Label' },
    } as any)[id as string]);
    const root = malware({
      refs: {
        createdBy: { existing: 'identity-1' },
        objectMarking: [{ existing: 'marking-1' }],
        objectLabel: [{ existing: 'label-1' }, { pending: 'l1' }],
        externalReferences: [{ pending: 'e1' }],
      },
    });
    const values = { mainEntityLookupPending: [root], pendingObjects: [label('l1'), extRef('e1')] };
    const [entity] = await materializePendingRoots(context, user, [root], values, []) as any[];
    expect(entity.createdBy).toEqual({ internal_id: 'identity-1', standard_id: 'identity--1' });
    expect(entity.objectMarking).toEqual([{ internal_id: 'marking-1', standard_id: 'marking-definition--1' }]);
    expect(entity.objectLabel).toEqual([{ value: 'existing-label' }, { value: 'new-label' }]);
    expect(entity.externalReferences).toEqual([{ source_name: 'src', url: 'https://example.com' }]);
  });

  it('should reject an existing ref that is not accessible or of the wrong type', async () => {
    vi.mocked(internalLoadById).mockResolvedValueOnce(undefined as any);
    await expect(materializePendingRoots(context, user, [malware({ refs: { objectMarking: [{ existing: 'x' }] } })], {}, []))
      .rejects.toThrow('Pending ref does not target an accessible entity of the expected type');
    vi.mocked(internalLoadById).mockResolvedValueOnce({ internal_id: 'x', entity_type: 'Malware' } as any);
    await expect(materializePendingRoots(context, user, [malware({ refs: { createdBy: { existing: 'x' } } })], {}, []))
      .rejects.toThrow('Pending ref does not target an accessible entity of the expected type');
  });

  it('should attach uploaded files as base64 x_opencti_files', async () => {
    const uploads = [{ filename: 'report.pdf', mimetype: 'application/pdf', data: 'ZGF0YQ==' }];
    const root = malware({ files: [{ name: 'renamed.pdf', uploadIndex: 0 }] });
    const [entity] = await materializePendingRoots(context, user, [root], {}, uploads) as any[];
    expect(entity.x_opencti_files).toEqual([{ name: 'renamed.pdf', data: 'ZGF0YQ==', mime_type: 'application/pdf' }]);
  });

  it('should ignore reference and file fields of the legacy input', async () => {
    const root = malware({ input: { name: 'Pending', createdBy: 'id', objectMarking: ['m'], files: [{ name: 'x' }], embedded: [true] } });
    const [entity] = await materializePendingRoots(context, user, [root], {}, []) as any[];
    expect(entity.createdBy).toBeUndefined();
    expect(entity.objectMarking).toBeUndefined();
    expect(entity.x_opencti_files).toBeUndefined();
    expect(entity.embedded).toBeUndefined();
  });
});

describe('readUploads', () => {
  it('should read each upload as base64, in order', async () => {
    const upload = (filename: string, content: string) => Promise.resolve({
      filename,
      mimetype: 'text/plain',
      createReadStream: () => Readable.from([Buffer.from(content)]),
    });
    const result = await readUploads([upload('a.txt', 'aaa'), upload('b.txt', 'bbb')]);
    expect(result).toEqual([
      { filename: 'a.txt', mimetype: 'text/plain', data: Buffer.from('aaa').toString('base64') },
      { filename: 'b.txt', mimetype: 'text/plain', data: Buffer.from('bbb').toString('base64') },
    ]);
    expect(await readUploads(undefined)).toEqual([]);
  });

  it('should read only the requested uploads', async () => {
    const createReadStream = vi.fn(() => Readable.from([Buffer.from('x')]));
    const skipped = vi.fn(() => Readable.from([Buffer.from('y')]));
    const result = await readUploads([
      Promise.resolve({ filename: 'a', mimetype: 'text/plain', createReadStream }),
      Promise.resolve({ filename: 'b', mimetype: 'text/plain', createReadStream: skipped }),
    ], new Map([[0, 1]]));
    expect(result[0].filename).toBe('a');
    expect(result[1]).toBeUndefined();
    expect(skipped).not.toHaveBeenCalled();
  });

  it('should reject uploads that are too large together', async () => {
    const chunk = Buffer.alloc(MAX_PENDING_UPLOAD_BYTES / 2 + 1);
    const big = () => Promise.resolve({ filename: 'big', mimetype: 'text/plain', createReadStream: () => Readable.from([chunk]) });
    await expect(readUploads([big()])).resolves.toHaveLength(1);
    await expect(readUploads([big(), big()])).rejects.toThrow('The uploads of the form are too large');
    // a single upload streamed in several chunks is capped as well
    const chunks = Promise.resolve({ filename: 'c', mimetype: 'text/plain', createReadStream: () => Readable.from([chunk, chunk]) });
    await expect(readUploads([chunks])).rejects.toThrow('The uploads of the form are too large');
    // an upload copied twice in the bundle counts twice
    await expect(readUploads([big()], new Map([[0, 2]]))).rejects.toThrow('The uploads of the form are too large');
  });
});

describe('resolvePendingFieldRefs', () => {
  const pool = [label('l1'), extRef('e1'), { id: 'm1', entityType: 'Malware', input: { name: 'M' } }];

  it('should replace pending entries of direct fields by the label name or the external reference attributes', () => {
    const values = {
      labels: ['existing-name', { pending: 'l1' }],
      refs: [{ pending: 'e1' }, 'ext-id'],
      mainEntityGroups: [{ labels: [{ pending: 'l1' }] }],
      pendingObjects: pool,
    };
    const resolved = resolvePendingFieldRefs(values);
    expect(resolved.labels).toEqual(['existing-name', 'new-label']);
    expect(resolved.refs).toEqual([{ source_name: 'src', url: 'https://example.com' }, 'ext-id']);
    expect(resolved.mainEntityGroups).toEqual([{ labels: ['new-label'] }]);
  });

  it('should leave the pending roots and the pool untouched', () => {
    const root = malware({ refs: { objectLabel: [{ pending: 'l1' }] } });
    const values = { mainEntityLookupPending: [root], pendingObjects: pool };
    const resolved = resolvePendingFieldRefs(values);
    expect(resolved.mainEntityLookupPending).toEqual([root]);
    expect(resolved.pendingObjects).toEqual(pool);
  });

  it('should reject a dangling entry or an entry targeting something else than a label or external reference', () => {
    expect(() => resolvePendingFieldRefs({ labels: [{ pending: 'nope' }], pendingObjects: pool }))
      .toThrow('Pending field ref must target a pooled label or external reference');
    expect(() => resolvePendingFieldRefs({ labels: [{ pending: 'm1' }], pendingObjects: pool }))
      .toThrow('Pending field ref must target a pooled label or external reference');
  });
});

describe('files of pending objects', () => {
  const TOKEN_A = '00000000-0000-0000-0000-00000000000a';
  const TOKEN_B = '00000000-0000-0000-0000-00000000000b';
  const png = (data = 'cG5n') => ({ filename: 'img.png', mimetype: 'image/png', data });
  const image = (uploadIndex: number) => ({ name: `img${uploadIndex}.png`, uploadIndex, embedded: true });

  it('should turn the markdown images of a description into data URIs, in order', async () => {
    const root = malware({
      input: { name: 'M', description: `a ![one](opencti-image://temp/${TOKEN_A}) b ![two](opencti-image://temp/${TOKEN_B})` },
      files: [image(0), image(1)],
    });
    const uploads = [png('Zmlyc3Q='), png('c2Vjb25k')];
    const [entity] = await materializePendingRoots(context, user, [root], {}, uploads) as any[];
    expect(entity.description).toBe('a ![one](data:image/png;base64,Zmlyc3Q=) b ![two](data:image/png;base64,c2Vjb25k)');
    expect(entity.x_opencti_files).toBeUndefined();
  });

  it('should keep the attached files apart from the markdown images', async () => {
    const root = malware({
      input: { name: 'M', description: `![one](opencti-image://temp/${TOKEN_A})` },
      files: [image(0), { name: 'evidence.pdf', mime_type: 'application/pdf', uploadIndex: 1 }],
    });
    const uploads = [png(), { filename: 'evidence.pdf', mimetype: 'application/pdf', data: 'cGRm' }];
    const [entity] = await materializePendingRoots(context, user, [root], {}, uploads) as any[];
    expect(entity.description).toContain('data:image/png;base64,cG5n');
    expect(entity.x_opencti_files).toEqual([{ name: 'evidence.pdf', data: 'cGRm', mime_type: 'application/pdf' }]);
  });

  it('should reject a markdown image of an unsupported type or a too large one', async () => {
    const input = { name: 'M', description: `![one](opencti-image://temp/${TOKEN_A})` };
    await expect(materializePendingRoots(context, user, [malware({ input, files: [image(0)] })], {}, [{ filename: 'a.svg', mimetype: 'image/svg+xml', data: 'PHN2Zz4=' }]))
      .rejects.toThrow('Unsupported markdown embedded image mime type');
    const tooLarge = Buffer.alloc(5 * 1024 * 1024 + 1).toString('base64');
    await expect(materializePendingRoots(context, user, [malware({ input, files: [image(0)] })], {}, [png(tooLarge)]))
      .rejects.toThrow('Markdown embedded image is too large');
  });

  it('should give the images to the tokens in the order of their first appearance, a repeated token counting once', async () => {
    const root = malware({
      input: {
        name: 'M',
        description: `![b](opencti-image://temp/${TOKEN_B}) and ![a](opencti-image://temp/${TOKEN_A}) and again ![b](opencti-image://temp/${TOKEN_B})`,
      },
      files: [image(0), image(1)],
    });
    const [entity] = await materializePendingRoots(context, user, [root], {}, [png('Zmlyc3Q='), png('c2Vjb25k')]) as any[];
    expect(entity.description).toBe('![b](data:image/png;base64,Zmlyc3Q=) and ![a](data:image/png;base64,c2Vjb25k) and again ![b](data:image/png;base64,Zmlyc3Q=)');
  });

  it('should reject more images than temp tokens in the description, and the other way round', async () => {
    const one = { name: 'M', description: `![one](opencti-image://temp/${TOKEN_A})` };
    const message = 'The embedded images do not match the image references of the description';
    await expect(materializePendingRoots(context, user, [malware({ input: one, files: [image(0), image(1)] })], {}, [png(), png()])).rejects.toThrow(message);
    const two = { name: 'M', description: `![one](opencti-image://temp/${TOKEN_A}) ![two](opencti-image://temp/${TOKEN_B})` };
    await expect(materializePendingRoots(context, user, [malware({ input: two, files: [image(0)] })], {}, [png()])).rejects.toThrow(message);
    // a token nobody provides an image for, with no file at all
    await expect(materializePendingRoots(context, user, [malware({ input: one })], {}, [])).rejects.toThrow(message);
    // an image with no token to replace
    await expect(materializePendingRoots(context, user, [malware({ files: [image(0)] })], {}, [png()])).rejects.toThrow(message);
    // the same applies to the description of a pooled external reference
    const pooled: PendingObject = { id: 'e1', entityType: 'External-Reference', input: { source_name: 's', description: one.description } };
    const root = malware({ refs: { externalReferences: [{ pending: 'e1' }] } });
    await expect(materializePendingRoots(context, user, [root], { pendingObjects: [pooled] }, [])).rejects.toThrow(message);
  });

  it('should check the mime type of the upload, not the one the client declares', async () => {
    const input = { name: 'M', description: `![one](opencti-image://temp/${TOKEN_A})` };
    const svg = { filename: 'a.svg', mimetype: 'image/svg+xml', data: 'PHN2Zz4=' };
    const declaredPng = { name: 'a.png', uploadIndex: 0, embedded: true, mime_type: 'image/png' };
    await expect(materializePendingRoots(context, user, [malware({ input, files: [declaredPng] })], {}, [svg]))
      .rejects.toThrow('Unsupported markdown embedded image mime type');
    const declaredSvg = { name: 'a.png', uploadIndex: 0, embedded: true, mime_type: 'image/svg+xml' };
    const [entity] = await materializePendingRoots(context, user, [malware({ input, files: [declaredSvg] })], {}, [png('Zmlyc3Q=')]) as any[];
    expect(entity.description).toBe('![one](data:image/png;base64,Zmlyc3Q=)');
  });

  it('should carry the files and the markdown images of a pooled external reference', async () => {
    const pooled: PendingObject = {
      id: 'e1',
      entityType: 'External-Reference',
      input: { source_name: 'src', description: `![shot](opencti-image://temp/${TOKEN_A})` },
      files: [image(0), { name: 'report.pdf', uploadIndex: 1 }],
    };
    const root = malware({ refs: { externalReferences: [{ pending: 'e1' }] } });
    const uploads = [png(), { filename: 'report.pdf', mimetype: 'application/pdf', data: 'cGRm' }];
    const values = { mainEntityLookupPending: [root], pendingObjects: [pooled] };
    expect(() => validatePendingPayload(values, 2)).not.toThrow();
    const [entity] = await materializePendingRoots(context, user, [root], values, uploads) as any[];
    expect(entity.externalReferences).toEqual([{
      source_name: 'src',
      description: '![shot](data:image/png;base64,cG5n)',
      x_opencti_files: [{ name: 'report.pdf', data: 'cGRm', mime_type: 'application/pdf' }],
    }]);
    // the same pooled reference reached from a direct field
    const resolved = resolvePendingFieldRefs({ refs: [{ pending: 'e1' }], pendingObjects: [pooled] }, uploads);
    expect(resolved.refs).toEqual(entity.externalReferences);
  });

  it('should reject a pooled file pointing outside the uploads', () => {
    const pooled = { ...extRef('e1'), files: [{ name: 'a.pdf', uploadIndex: 3 }] };
    expect(() => validatePendingPayload({ pendingObjects: [pooled] }, 1)).toThrow('Pending file refers to a missing upload');
  });
});

describe('withPendingExternalReferenceFiles', () => {
  it('should put the files with data on the matching external reference of the STIX object', () => {
    const stix = { external_references: [{ source_name: 'existing' }, { source_name: 'pending' }] };
    const entity = {
      externalReferences: [
        { source_name: 'existing', x_opencti_files: [{ id: 'import/x', name: 'stored.pdf' }] },
        { source_name: 'pending', x_opencti_files: [{ name: 'a.pdf', data: 'cGRm', mime_type: 'application/pdf' }] },
      ],
    };
    withPendingExternalReferenceFiles(stix, entity);
    expect(stix.external_references[0]).toEqual({ source_name: 'existing' });
    expect(stix.external_references[1]).toEqual({ source_name: 'pending', x_opencti_files: [{ name: 'a.pdf', data: 'cGRm', mime_type: 'application/pdf' }] });
  });
});
