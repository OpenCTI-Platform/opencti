import { describe, expect, it } from 'vitest';
import { extractResolvedFiltersFromInstance } from '../../../src/manager/cacheManager';
import type { BasicStoreCommon } from '../../../src/types/store';

const instanceOfPlaybookListenKnowledgeWithSelectedEntities = {
  playbook_definition: '{"nodes":[{"id":"id1","name":"Listen knowledge events","position":{"x":0,"y":0},"component_id":"PLAYBOOK_INTERNAL_DATA_STREAM","configuration":"{\\"create\\":true,\\"update\\":true,\\"delete\\":false,\\"filters\\":\\"{\\\\\\"mode\\\\\\":\\\\\\"and\\\\\\",\\\\\\"filters\\\\\\":[{\\\\\\"key\\\\\\":[\\\\\\"fromId\\\\\\"],\\\\\\"operator\\\\\\":\\\\\\"eq\\\\\\",\\\\\\"values\\\\\\":[\\\\\\"id2\\\\\\",\\\\\\"id3\\\\\\",\\\\\\"id4\\\\\\",\\\\\\"id5\\\\\\"],\\\\\\"mode\\\\\\":\\\\\\"or\\\\\\"}],\\\\\\"filterGroups\\\\\\":[]}\\"}"},{"id":"id6","name":"Send to notifier","position":{"x":0,"y":150},"component_id":"PLAYBOOK_NOTIFIER_COMPONENT","configuration":"{\\"notifiers\\":[\\"id7\\"],\\"authorized_members\\":[{\\"label\\":\\"admin@opencti.io\\",\\"value\\":\\"id8\\",\\"type\\":\\"User\\"}]}"}],"links":[{"id":"id9","from":{"id":"id1","port":"out"},"to":{"id":"id6"}}]}',
  entity_type: 'Playbook',
} as unknown as BasicStoreCommon;

const instanceOfPlaybookListenKnowledgeWithNoSelectedEntities = {
  playbook_definition: '{"nodes":[{"id":"02f24be8-5936-4c6e-bf9c-31b37e7ad1d9","name":"Listen knowledge events","position":{"x":0,"y":0},"component_id":"PLAYBOOK_INTERNAL_DATA_STREAM","configuration":"{\\"create\\":true,\\"update\\":false,\\"delete\\":false,\\"filters\\":\\"{\\\\\\"mode\\\\\\":\\\\\\"and\\\\\\",\\\\\\"filters\\\\\\":[{\\\\\\"key\\\\\\":[\\\\\\"entity_type\\\\\\"],\\\\\\"operator\\\\\\":\\\\\\"eq\\\\\\",\\\\\\"values\\\\\\":[\\\\\\"Malware\\\\\\"],\\\\\\"mode\\\\\\":\\\\\\"or\\\\\\"}],\\\\\\"filterGroups\\\\\\":[]}\\"}"},{"id":"1ffa6c60-5dd6-4430-ad23-9ebffcfe3d49","name":"Send to notifier","position":{"x":0,"y":150},"component_id":"PLAYBOOK_NOTIFIER_COMPONENT","configuration":"{\\"notifiers\\":[\\"f4ee7b33-006a-4b0d-b57d-411ad288653d\\"],\\"authorized_members\\":[{\\"label\\":\\"admin@opencti.io\\",\\"value\\":\\"88ec0c6a-13ce-5e39-b486-354fe4a7084f\\",\\"type\\":\\"User\\"}]}"}],"links":[{"id":"70196975-86da-4ab5-8a56-352b82c281bc","from":{"id":"02f24be8-5936-4c6e-bf9c-31b37e7ad1d9","port":"out"},"to":{"id":"1ffa6c60-5dd6-4430-ad23-9ebffcfe3d49"}}]}',
  entity_type: 'Playbook',
} as unknown as BasicStoreCommon;

const instanceOfPlaybookListenPIR = {
  playbook_definition: '{"nodes":[{"id":"id1","name":"Listen PIR events","position":{"x":0,"y":0},"component_id":"PLAYBOOK_DATA_STREAM_PIR","configuration":"{\\"inPirFilters\\":[{\\"label\\":\\"Test playbook\\",\\"value\\":\\"id2\\",\\"type\\":\\"Pir\\"}],\\"create\\":true,\\"update\\":false,\\"delete\\":false,\\"filters\\":\\"{\\\\\\"mode\\\\\\":\\\\\\"and\\\\\\",\\\\\\"filters\\\\\\":[{\\\\\\"key\\\\\\":[\\\\\\"entity_type\\\\\\"],\\\\\\"operator\\\\\\":\\\\\\"eq\\\\\\",\\\\\\"values\\\\\\":[\\\\\\"Threat-Actor-Group\\\\\\"],\\\\\\"mode\\\\\\":\\\\\\"or\\\\\\"}],\\\\\\"filterGroups\\\\\\":[]}\\"}"},{"id":"id3","name":"Send to notifier","position":{"x":0,"y":150},"component_id":"PLAYBOOK_NOTIFIER_COMPONENT","configuration":"{\\"notifiers\\":[\\"id4\\"],\\"authorized_members\\":[{\\"label\\":\\"admin@opencti.io\\",\\"value\\":\\"id5\\",\\"type\\":\\"User\\"}]}"}],"links":[{"id":"id6","from":{"id":"id1","port":"out"},"to":{"id":"id3"}}]}',
  entity_type: 'Playbook',
} as unknown as BasicStoreCommon;

describe('Cache Manager', () => {
  describe('Function extractResolvedFiltersFromInstance()', () => {
    describe('Specific case of playbooks', () => {
      it('should return correct ids when listen knowledge events and selected entities', async () => {
        const expectedResult :any[] = ['id2', 'id3', 'id4', 'id5'];
        const result = extractResolvedFiltersFromInstance(instanceOfPlaybookListenKnowledgeWithSelectedEntities);
        expect(result).toEqual(expectedResult);
      });

      it('should return correct ids when listen knowledge events with no selected entities', async () => {
        const expectedResult :any[] = [];
        const result = extractResolvedFiltersFromInstance(instanceOfPlaybookListenKnowledgeWithNoSelectedEntities);
        expect(result).toEqual(expectedResult);
      });

      it('should return correct ids listening to PIR events', async () => {
        const expectedResult :any[] = ['id2'];
        const result = extractResolvedFiltersFromInstance(instanceOfPlaybookListenPIR);
        expect(result).toEqual(expectedResult);
      });
    });
  });
});
