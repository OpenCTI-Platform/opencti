import { beforeEach, describe, expect, it, vi } from 'vitest';
import { playbookImport } from '../../../src/modules/playbook/playbook-domain';
import * as fileToContent from '../../../src/utils/fileToContent';
import type { AuthContext } from '../../../src/types/user';
import { ADMIN_USER } from '../../utils/testQuery';
import type { FileHandle } from 'fs/promises';
import * as UserActionListener from '../../../src/listener/UserActionListener';
import { ENTITY_TYPE_PLAYBOOK } from '../../../src/modules/playbook/playbook-types';

describe('playbook-domain', () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  describe('playbookImport', () => {
    const parsedDataMock = {
      openCTI_version: '6.9.0',
      type: 'playbook',
      configuration: {
        name: 'test config',
        description: '',
        playbook_start: 'ce1413d0-d93b-45ae-9cda-24fea1ab67b7',
        playbook_definition: '{"nodes":[{"id":"ce1413d0-d93b-45ae-9cda-24fea1ab67b7","name":"Listen knowledge events","position":{"x":0,"y":0},"component_id":"PLAYBOOK_INTERNAL_DATA_STREAM","configuration":"{\\"create\\":true,\\"update\\":true,\\"delete\\":false,\\"filters\\":\\"{\\\\\\"mode\\\\\\":\\\\\\"and\\\\\\",\\\\\\"filters\\\\\\":[],\\\\\\"filterGroups\\\\\\":[]}\\",\\"canEnrollManually\\":true}"},{"id":"01c5e873-df20-41db-805b-00ac26d0de88","name":"Apply predefined rule","position":{"x":0,"y":150},"component_id":"PLAYBOOK_RULE_COMPONENT","configuration":"{\\"rule\\":\\"resolve_container\\",\\"inferences\\":false}"},{"id":"78411f5e-e053-4e03-92c5-748845ec2de9","name":"Container wrapper","position":{"x":-100,"y":300},"component_id":"PLAYBOOK_CONTAINER_WRAPPER_COMPONENT","configuration":"{\\"actions\\":[],\\"all\\":true,\\"applyWithFilters\\":\\"{\\\\\\"mode\\\\\\":\\\\\\"and\\\\\\",\\\\\\"filters\\\\\\":[],\\\\\\"filterGroups\\\\\\":[]}\\",\\"container_type\\":\\"Feedback\\",\\"excludeMainElement\\":true}"},{"id":"2853a108-7d66-4904-aefa-67259308338a","name":"Send for ingestion","position":{"x":-100,"y":450},"component_id":"PLAYBOOK_INGESTION_COMPONENT","configuration":"{}"}],"links":[]}',
      },
    };
    const parsedDataOldVersionMock = { openCTI_version: '6.6.0', type: 'playbook', configuration: {} };
    const parsedDataWrongTypeMock = { openCTI_version: '7.260428.0', type: 'random', configuration: {} };
    const contextMock = { id: 'context' } as unknown as AuthContext;
    const fileMock = {} as unknown as Promise<FileHandle>;

    beforeEach(() => {
      vi.spyOn(UserActionListener, 'publishUserAction').mockResolvedValue([]);
    });

    it('should throw error if playbook from a too old octi version', async () => {
      vi.spyOn(fileToContent, 'extractContentFrom').mockResolvedValue(parsedDataOldVersionMock);

      await expect(playbookImport(contextMock, ADMIN_USER, fileMock)).rejects.toThrowError('Invalid version of the platform. Please upgrade your OpenCTI. Minimal version required: 6.7.14');
    });

    it('should throw error if parsedData is not of playbook type', async () => {
      vi.spyOn(fileToContent, 'extractContentFrom').mockResolvedValue(parsedDataWrongTypeMock);

      await expect(playbookImport(contextMock, ADMIN_USER, fileMock)).rejects.toThrowError('Invalid import type, must be playbook');
    });

    it('should update correctly a playbook imported with the old configuration', async () => {
      vi.spyOn(fileToContent, 'extractContentFrom').mockResolvedValue(parsedDataMock);
      const updatedPlaybookDefinition = '{"nodes":[{"id":"ce1413d0-d93b-45ae-9cda-24fea1ab67b7","name":"Listen knowledge events","position":{"x":0,"y":0},"component_id":"PLAYBOOK_INTERNAL_DATA_STREAM","configuration":"{\\"create\\":true,\\"update\\":true,\\"delete\\":false,\\"filters\\":\\"{\\\\\\"mode\\\\\\":\\\\\\"and\\\\\\",\\\\\\"filters\\\\\\":[],\\\\\\"filterGroups\\\\\\":[]}\\",\\"canEnrollManually\\":true}"},{"id":"01c5e873-df20-41db-805b-00ac26d0de88","name":"Apply predefined rule","position":{"x":0,"y":150},"component_id":"PLAYBOOK_RULE_COMPONENT","configuration":"{\\"rule\\":\\"resolve_container\\",\\"inferences\\":false}"},{"id":"78411f5e-e053-4e03-92c5-748845ec2de9","name":"Container wrapper","position":{"x":-100,"y":300},"component_id":"PLAYBOOK_CONTAINER_WRAPPER_COMPONENT","configuration":"{\\"actions\\":[],\\"applyWithFilters\\":\\"{\\\\\\"mode\\\\\\":\\\\\\"and\\\\\\",\\\\\\"filters\\\\\\":[],\\\\\\"filterGroups\\\\\\":[]}\\",\\"container_type\\":\\"Feedback\\",\\"applyToElements\\":\\"all-except-main\\"}"},{"id":"2853a108-7d66-4904-aefa-67259308338a","name":"Send for ingestion","position":{"x":-100,"y":450},"component_id":"PLAYBOOK_INGESTION_COMPONENT","configuration":"{}"}],"links":[]}';

      const result = await playbookImport(contextMock, ADMIN_USER, fileMock);
      expect(UserActionListener.publishUserAction).toHaveBeenCalledWith(
        expect.objectContaining({
          user: ADMIN_USER,
          event_type: 'mutation',
          event_scope: 'create',
          event_access: 'extended',
          message: `import ${parsedDataMock.configuration.name} playbook`,
          context_data: expect.objectContaining({
            id: expect.any(String),
            entity_type: ENTITY_TYPE_PLAYBOOK,
            input: expect.objectContaining({
              entity_type: ENTITY_TYPE_PLAYBOOK,
              playbook_definition: updatedPlaybookDefinition,
              playbook_start: parsedDataMock.configuration.playbook_start,
            }),
          }),
        }),
      );
      expect(result).toBeTypeOf('string');
    });
  });
});
