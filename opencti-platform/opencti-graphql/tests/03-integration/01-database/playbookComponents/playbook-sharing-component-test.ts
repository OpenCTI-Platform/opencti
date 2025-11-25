import { describe, expect, it, vi, beforeEach, type MockInstance } from 'vitest';
import type { StixBundle, StixObject, StixOpenctiExtension } from '../../../../src/types/stix-2-1-common';
import type { BasicStoreObject } from '../../../../src/types/store';
import type { StixId } from '../../../../src/types/stix-2-0-common';
import { STIX_EXT_OCTI } from '../../../../src/types/stix-2-1-extensions';
import { PLAYBOOK_SHARING_COMPONENT } from '../../../../src/modules/playbook/playbook-components';
import { generateStandardId } from '../../../../src/schema/identifier';
import { ENTITY_TYPE_IDENTITY_ORGANIZATION } from '../../../../src/modules/organization/organization-types';
import * as middlewareLoader from '../../../../src/database/middleware-loader';
import * as access from '../../../../src/utils/access';

export const sharing_component_bundle = {
  id: '411628bf-745b-43f6-8194-cbe441edecfd',
  objects: [
    {
      confidence: 100,
      created: '2025-03-25T09:59:10.000Z',
      description: 'fff',
      extensions: {
        'extension-definition--ea279b3e-5c71-4632-ac08-831c66a786ba': {
          created_at: '2025-03-25T09:59:17.024Z',
          creator_ids: [
            '88ec0c6a-13ce-5e39-b486-354fe4a7084f',
          ],
          extension_type: 'property-extension',
          id: '82e80255-9793-4283-b34b-872b30f23f57',
          type: 'Report',
          updated_at: '2025-03-25T09:59:44.832Z',
          workflow_id: 'a4b90e6f-06ae-461a-8dac-666cdb4a5ae7',
        },
      },
      id: 'report--b70b1781-f963-5790-9fe7-55aec16c05f4',
      lang: 'en',
      modified: '2025-03-25T09:59:44.832Z',
      name: 'report 28',
      object_refs: [
        'campaign--fdcacc8e-de4d-5a13-8886-401d363664fd',
      ],
      published: '2025-03-25T09:59:10.000Z',
      spec_version: '2.1',
      type: 'report',
    },
    {
      id: 'campaign--fdcacc8e-de4d-5a13-8886-401d363664fd',
      spec_version: '2.1',
      type: 'campaign',
      extensions: {
        'extension-definition--ea279b3e-5c71-4632-ac08-831c66a786ba': {
          extension_type: 'property-extension',
          id: '21df79ac-4edf-40c5-bc04-a0122dbc4e39',
          type: 'Campaign',
          created_at: '2015-05-15T09:12:16.432Z',
          updated_at: '2025-03-26T10:00:10.363Z',
          is_inferred: false,
          creator_ids: [
            '88ec0c6a-13ce-5e39-b486-354fe4a7084f',
          ],
        },
      },
      created: '2020-02-29T14:48:31.601Z',
      modified: '2025-04-10T16:34:18.572Z',
      revoked: false,
      confidence: 100,
      lang: 'en',
      labels: [
        'campaign',
      ],
      name: 'admin@338',
      description: 'description',
      first_seen: '2008-01-07T00:00:00.000Z',
    },
  ],
  spec_version: '2.1',
  type: 'bundle',
} as unknown as StixBundle;

describe('PLAYBOOK_SHARING_COMPONENT', () => {
  const reportId = 'report--5f78a68b-2c4d-5e6f-beaa-7b987b0e7165';
  const secondObjectId = 'indicator--second-object';

  const inputBundle: StixBundle = {
    id: '81b65094-7fe7-40df-a695-43d30b3656b1',
    spec_version: '2.1',
    type: 'bundle',
    objects: [
      {
        id: reportId,
        spec_version: '2.1',
        type: 'report',
        extensions: {
          [STIX_EXT_OCTI]: {
            extension_type: 'property-extension',
            id: 'a2b9d1b8-ef96-45e6-916c-61fa419aecb6',
            type: 'Report',
            created_at: '2026-01-05T08:36:57.202Z',
            updated_at: '2026-01-07T08:56:54.200Z',
            is_inferred: false,
            creator_ids: ['41213f4f-cd58-4e1d-accf-3a007c8f3aaf'],
            workflow_id: '45959cc6-ae18-4add-af13-8aa24e2560a2',
          } as StixOpenctiExtension,
        },
        created: '2026-01-05T08:36:56.000Z',
        modified: '2026-01-07T08:56:54.200Z',
        revoked: false,
        confidence: 100,
        lang: 'en',
        name: 'Test Report',
        description: 'Test description',
        report_types: ['internal-report'],
        published: '2026-01-05T08:36:56.000Z',
        object_refs: [],
      } as StixObject,
    ],
  } as StixBundle;

  const createPlaybookNode = (organizations: string[], all = false) => ({
    id: 'playbook-node',
    name: 'share-node',
    component_id: 'PLAYBOOK_SHARING_COMPONENT',
    configuration: {
      organizations,
      all,
    },
  });

  const createPlaybookNodeWithObjectOrgs = (organizations: { label: string; value: string }[], all = false) => ({
    id: 'playbook-node',
    name: 'share-node',
    component_id: 'PLAYBOOK_SHARING_COMPONENT',
    configuration: {
      organizations,
      all,
    },
  });

  const createMockOrganization = (name: string): Partial<BasicStoreObject> => ({
    id: `org-internal-${name}`,
    standard_id: generateStandardId(ENTITY_TYPE_IDENTITY_ORGANIZATION, { name }) as StixId,
  });

  const createSecondObject = (): StixObject => ({
    id: secondObjectId,
    spec_version: '2.1',
    type: 'indicator',
    extensions: {
      [STIX_EXT_OCTI]: {
        extension_type: 'property-extension',
        id: 'second-ext-id',
        type: 'Indicator',
      } as StixOpenctiExtension,
    },
  } as StixObject);

  const getExtension = (bundle: StixBundle, objectId: string): StixOpenctiExtension => {
    const obj = bundle.objects.find((o) => o.id === objectId) as StixObject;
    return obj.extensions![STIX_EXT_OCTI] as StixOpenctiExtension;
  };

  type InternalFindByIdsSpy = MockInstance<typeof middlewareLoader.internalFindByIds>;
  let internalFindByIdsSpy: InternalFindByIdsSpy;

  beforeEach(() => {
    vi.clearAllMocks();
    vi.spyOn(access, 'executionContext').mockReturnValue({} as any);
    internalFindByIdsSpy = vi.spyOn(middlewareLoader, 'internalFindByIds');
  });

  describe('when organizations array is empty or not found', () => {
    it('should return bundle unchanged when organizations array is empty', async () => {
      internalFindByIdsSpy.mockResolvedValue([]);

      const bundle = structuredClone(inputBundle);

      const result = await PLAYBOOK_SHARING_COMPONENT.executor({
        dataInstanceId: reportId,
        eventId: '',
        executionId: '',
        playbookId: '',
        previousPlaybookNodeId: undefined,
        previousStepBundle: null as StixBundle | null,
        bundle,
        playbookNode: createPlaybookNode([]),
      });

      expect(result.output_port).toBe('out');
      expect(getExtension(result.bundle, reportId).granted_refs).toBeUndefined();
    });

    it('should return bundle unchanged when no matching organizations found in database', async () => {
      internalFindByIdsSpy.mockResolvedValue([]);

      const bundle = structuredClone(inputBundle);

      const result = await PLAYBOOK_SHARING_COMPONENT.executor({
        dataInstanceId: reportId,
        eventId: '',
        executionId: '',
        playbookId: '',
        previousPlaybookNodeId: undefined,
        previousStepBundle: null as StixBundle | null,
        bundle,
        playbookNode: createPlaybookNode(['org-not-found']),
      });

      expect(result.output_port).toBe('out');
      expect(getExtension(result.bundle, reportId).granted_refs).toBeUndefined();
    });
  });

  describe('when adding granted_refs to single object', () => {
    it('should add granted_refs to dataInstanceId object', async () => {
      const mockOrg = createMockOrganization('TestOrg');

      internalFindByIdsSpy.mockResolvedValue([mockOrg as BasicStoreObject]);

      const bundle = structuredClone(inputBundle);

      const result = await PLAYBOOK_SHARING_COMPONENT.executor({
        dataInstanceId: reportId,
        eventId: '',
        executionId: '',
        playbookId: '',
        previousPlaybookNodeId: undefined,
        previousStepBundle: null as StixBundle | null,
        bundle,
        playbookNode: createPlaybookNode([mockOrg.id!], false),
      });

      expect(internalFindByIdsSpy).toHaveBeenCalled();
      expect(result.output_port).toBe('out');

      const ext = getExtension(result.bundle, reportId);
      expect(ext.granted_refs).toBeDefined();
      expect(ext.granted_refs).toContain(mockOrg.standard_id);
      expect(ext.granted_refs).toHaveLength(1);
    });

    it('should handle organizations as objects with label and value properties', async () => {
      const mockOrg = createMockOrganization('TestOrg');

      internalFindByIdsSpy.mockResolvedValue([mockOrg as BasicStoreObject]);

      const bundle = structuredClone(inputBundle);

      const result = await PLAYBOOK_SHARING_COMPONENT.executor({
        dataInstanceId: reportId,
        eventId: '',
        executionId: '',
        playbookId: '',
        previousPlaybookNodeId: undefined,
        previousStepBundle: null as StixBundle | null,
        bundle,
        playbookNode: createPlaybookNodeWithObjectOrgs([{ label: 'Test Organization', value: mockOrg.id! }], false),
      });

      expect(result.output_port).toBe('out');

      const ext = getExtension(result.bundle, reportId);
      expect(ext.granted_refs).toContain(mockOrg.standard_id);
    });

    it('should add multiple organizations to granted_refs', async () => {
      const mockOrg1 = createMockOrganization('Org1');
      const mockOrg2 = createMockOrganization('Org2');

      internalFindByIdsSpy.mockResolvedValue([
        mockOrg1 as BasicStoreObject,
        mockOrg2 as BasicStoreObject,
      ]);

      const bundle = structuredClone(inputBundle);

      const result = await PLAYBOOK_SHARING_COMPONENT.executor({
        dataInstanceId: reportId,
        eventId: '',
        executionId: '',
        playbookId: '',
        previousPlaybookNodeId: undefined,
        previousStepBundle: null as StixBundle | null,
        bundle,
        playbookNode: createPlaybookNode([mockOrg1.id!, mockOrg2.id!], false),
      });

      const ext = getExtension(result.bundle, reportId);
      expect(ext.granted_refs).toContain(mockOrg1.standard_id);
      expect(ext.granted_refs).toContain(mockOrg2.standard_id);
      expect(ext.granted_refs).toHaveLength(2);
    });

    it('should append to existing granted_refs', async () => {
      const existingOrg = createMockOrganization('ExistingOrg');
      const newOrg = createMockOrganization('NewOrg');

      internalFindByIdsSpy.mockResolvedValue([newOrg as BasicStoreObject]);

      const bundle = structuredClone(inputBundle);
      (bundle.objects[0].extensions[STIX_EXT_OCTI] as StixOpenctiExtension).granted_refs = [existingOrg.standard_id!];

      const result = await PLAYBOOK_SHARING_COMPONENT.executor({
        dataInstanceId: reportId,
        eventId: '',
        executionId: '',
        playbookId: '',
        previousPlaybookNodeId: undefined,
        previousStepBundle: null as StixBundle | null,
        bundle,
        playbookNode: createPlaybookNode([newOrg.id!], false),
      });

      const ext = getExtension(result.bundle, reportId);
      expect(ext.granted_refs).toContain(existingOrg.standard_id);
      expect(ext.granted_refs).toContain(newOrg.standard_id);
      expect(ext.granted_refs).toHaveLength(2);
    });
  });

  describe('when bundle contains multiple objects', () => {
    // TODO: add test for all=true when cascading of sharing/unshare will be resolved
    it.skip('should add granted_refs to all objects when all=true', async () => {
      const mockOrg = createMockOrganization('TestOrg');

      internalFindByIdsSpy.mockResolvedValue([mockOrg as BasicStoreObject]);

      const bundle = structuredClone(inputBundle);
      bundle.objects.push(createSecondObject());

      const result = await PLAYBOOK_SHARING_COMPONENT.executor({
        dataInstanceId: reportId,
        eventId: '',
        executionId: '',
        playbookId: '',
        previousPlaybookNodeId: undefined,
        previousStepBundle: null as StixBundle | null,
        bundle,
        playbookNode: createPlaybookNode([mockOrg.id!], true),
      });

      const reportExt = getExtension(result.bundle, reportId);
      expect(reportExt.granted_refs).toContain(mockOrg.standard_id);

      const secondExt = getExtension(result.bundle, secondObjectId);
      expect(secondExt.granted_refs).toContain(mockOrg.standard_id);
    });
  });
});
