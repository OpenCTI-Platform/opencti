import { afterAll, describe, expect, it } from 'vitest';
import { findById, playbookDelete, playbookImport } from '../../../../src/modules/playbook/playbook-domain';
import { ADMIN_USER, testContext } from '../../../utils/testQuery';
import { open } from 'fs/promises';
import { ENTITY_TYPE_PLAYBOOK } from '../../../../src/modules/playbook/playbook-types';
import { join } from 'path';

describe('playbook-domain', () => {
  describe('playbookImport', () => {
    const playbookCreatedIds: string[] = [];

    afterAll(async () => {
      for (const id of playbookCreatedIds) {
        await playbookDelete(testContext, ADMIN_USER, id);
      }
    });

    it('should throw error if playbook from a too old octi version', async () => {
      const filePath = join(__dirname, 'testData/imported-playbook-with-old-version.json');
      const fileHandle = open(filePath);

      await expect(playbookImport(testContext, ADMIN_USER, fileHandle)).rejects.toThrowError('Invalid version of the platform. Please upgrade your OpenCTI. Minimal version required: 6.7.14');
    });

    it('should throw error if parsedData is not of playbook type', async () => {
      const filePath = join(__dirname, 'testData/imported-playbook-with-wrong-type.json');
      const fileHandle = open(filePath);

      await expect(playbookImport(testContext, ADMIN_USER, fileHandle)).rejects.toThrowError('Invalid import type, must be playbook');
    });

    it('should update correctly a playbook imported with the old configuration', async () => {
      const filePath = join(__dirname, 'testData/imported-playbook-with-old-scope.json');
      const fileHandle = open(filePath);
      const updatedPlaybookDefinition = '{"nodes":[{"id":"ce1413d0-d93b-45ae-9cda-24fea1ab67b7","name":"Listen knowledge events","position":{"x":0,"y":0},"component_id":"PLAYBOOK_INTERNAL_DATA_STREAM","configuration":"{\\"create\\":true,\\"update\\":true,\\"delete\\":false,\\"filters\\":\\"{\\\\\\"mode\\\\\\":\\\\\\"and\\\\\\",\\\\\\"filters\\\\\\":[],\\\\\\"filterGroups\\\\\\":[]}\\",\\"canEnrollManually\\":true}"},{"id":"01c5e873-df20-41db-805b-00ac26d0de88","name":"Apply predefined rule","position":{"x":0,"y":150},"component_id":"PLAYBOOK_RULE_COMPONENT","configuration":"{\\"rule\\":\\"resolve_container\\",\\"inferences\\":false}"},{"id":"78411f5e-e053-4e03-92c5-748845ec2de9","name":"Container wrapper","position":{"x":-100,"y":300},"component_id":"PLAYBOOK_CONTAINER_WRAPPER_COMPONENT","configuration":"{\\"actions\\":[],\\"applyWithFilters\\":\\"{\\\\\\"mode\\\\\\":\\\\\\"and\\\\\\",\\\\\\"filters\\\\\\":[],\\\\\\"filterGroups\\\\\\":[]}\\",\\"container_type\\":\\"Feedback\\",\\"applyToElements\\":\\"all-except-main\\"}"},{"id":"2853a108-7d66-4904-aefa-67259308338a","name":"Send for ingestion","position":{"x":-100,"y":450},"component_id":"PLAYBOOK_INGESTION_COMPONENT","configuration":"{}"}],"links":[]}';

      const importPlaybookId = await playbookImport(testContext, ADMIN_USER, fileHandle);
      playbookCreatedIds.push(importPlaybookId);

      const playbook = await findById(testContext, ADMIN_USER, importPlaybookId);

      expect(playbook).toBeDefined();
      expect(playbook.name).toEqual('test config');
      expect(playbook.playbook_definition).toEqual(updatedPlaybookDefinition);
      expect(playbook.playbook_start).toEqual('ce1413d0-d93b-45ae-9cda-24fea1ab67b7');
      expect(playbook.entity_type).toEqual(ENTITY_TYPE_PLAYBOOK);
      expect(playbook.id).toEqual(importPlaybookId);
    });
  });
});
