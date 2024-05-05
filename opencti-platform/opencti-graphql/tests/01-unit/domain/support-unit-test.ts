import { describe, expect, it } from 'vitest';
import { computePackageEntityChanges, findAllSupportFiles } from '../../../src/modules/support/support-domain';
import type { BasicStoreEntitySupportPackage } from '../../../src/modules/support/support-types';
import { type EditInput, EditOperation, PackageStatus } from '../../../src/generated/graphql';
import { SUPPORT_LOG_FILE_PREFIX } from '../../../src/config/conf';

describe('Testing support package filesystem tools - findAllSupportFiles', () => {
  it('should find all support files in list', async () => {
    const filesFound = findAllSupportFiles([
      'support.2024-04-23',
      'support.2022-06-29',
      'crapfile.log',
      '.stuff',
      'support.2024-04-28',
      'support.2024-04-27'
    ], SUPPORT_LOG_FILE_PREFIX);

    expect(filesFound.length).toBe(4);
  });

  it('should find all support files even if there is only one', async () => {
    const filesFound = findAllSupportFiles([
      '.caa4b3be024451942bcf5b2b03dc380049c97ba1-audit.json',
      '2b165a0f-6dc9-4c59-9df1-d9c38dd616a6.zip',
      'support.2024-04-08',
    ], SUPPORT_LOG_FILE_PREFIX);

    expect(filesFound.length).toBe(1);
    expect(filesFound[0]).toBe('support.2024-04-08');
  });

  it('should not crash and find nothing on empty list', async () => {
    const fileFound = findAllSupportFiles([], SUPPORT_LOG_FILE_PREFIX);
    expect(fileFound.length).toBe(0);
  });
});

describe('Testing support package status changes', () => {
  it('should add first node in progress', async () => {
    const packageEntity: Partial<BasicStoreEntitySupportPackage> = {
      id: '2-nodes-pf-only-one-send-support-data',
      package_status: PackageStatus.InProgress,
      nodes_status: undefined,
      nodes_count: 2
    };

    const editResult: EditInput[] = computePackageEntityChanges(packageEntity as BasicStoreEntitySupportPackage, PackageStatus.InProgress, 'newNodeId');
    expect(editResult.length, 'One node status should be added in the list').toBe(1);
    expect(editResult[0].operation).toBe(EditOperation.Replace);
  });

  it('should not be overall READY if waiting for other nodes log status', async () => {
    const packageEntity: Partial<BasicStoreEntitySupportPackage> = {
      id: 'platform-with-2-nodes',
      package_status: PackageStatus.InProgress,
      nodes_status: [
        {
          node_id: 'firstNodeId',
          package_status: PackageStatus.InProgress,
        }],
      nodes_count: 2
    };

    const editResult: EditInput[] = computePackageEntityChanges(packageEntity as BasicStoreEntitySupportPackage, PackageStatus.Ready, 'firstNodeId');
    expect(editResult.length, 'Only the node status should be updated, overall status is still in progress despite first node is ready.').toBe(1);
    expect(editResult[0].operation).toBe(EditOperation.Replace);
    expect(editResult[0].value.length, 'Expecting 1 node status in the list.').toBe(1);
  });

  it('should add another node in progress', async () => {
    const packageEntity: Partial<BasicStoreEntitySupportPackage> = {
      id: '3-nodes-pf',
      package_status: PackageStatus.InProgress,
      nodes_status: [
        {
          node_id: 'firstNodeId',
          package_status: PackageStatus.InProgress,
        },
        { node_id: 'secondNodeId',
          package_status: PackageStatus.InProgress,
        }],
      nodes_count: 3
    };

    const editResult: EditInput[] = computePackageEntityChanges(packageEntity as BasicStoreEntitySupportPackage, PackageStatus.Ready, 'newNodeId');
    expect(editResult.length).toBe(1);
    expect(editResult[0].operation).toBe(EditOperation.Replace);
    expect(editResult[0].value.length, 'Expecting 3 nodes status in the list.').toBe(3);
  });

  it('should update existing node as ready', async () => {
    const packageEntity: Partial<BasicStoreEntitySupportPackage> = {
      id: 'aaaaaaaaaaaaaaaaaaaaaaaa',
      package_status: PackageStatus.InProgress,
      nodes_status: [
        {
          node_id: 'firstNodeId',
          package_status: PackageStatus.InProgress,
        },
        { node_id: 'secondNodeId',
          package_status: PackageStatus.InProgress,
        }],
      nodes_count: 2
    };

    const editResult: EditInput[] = computePackageEntityChanges(packageEntity as BasicStoreEntitySupportPackage, PackageStatus.Ready, 'firstNodeId');
    expect(editResult.length).toBe(1);
    expect(editResult[0].operation).toBe(EditOperation.Replace);
    expect(editResult[0].value.length, 'Expecting 2 nodes status in the list.').toBe(2);
  });

  it('should update the last node as ready, update global status', async () => {
    const packageEntity: Partial<BasicStoreEntitySupportPackage> = {
      id: '3-nodes-waiting-for-last-ready',
      package_status: PackageStatus.InProgress,
      nodes_status: [
        {
          node_id: 'firstNodeId',
          package_status: PackageStatus.Ready,
        },
        { node_id: 'secondNodeId',
          package_status: PackageStatus.InProgress,
        },
        {
          node_id: 'thirdNodeId',
          package_status: PackageStatus.Ready,
        }],
      nodes_count: 3
    };

    const editResult: EditInput[] = computePackageEntityChanges(packageEntity as BasicStoreEntitySupportPackage, PackageStatus.Ready, 'secondNodeId');
    expect(editResult.length).toBe(2);
    expect(editResult[0].key).toBe('package_status');
    expect(editResult[0].value[0], 'Overall status must be change to READY.').toBe(PackageStatus.Ready);
    expect(editResult[1].operation).toBe(EditOperation.Replace);
    expect(editResult[1].value.length, 'Expecting 3 nodes status in the list.').toBe(3);
  });

  it('should update the last node as Ready, update global status in InError if some error', async () => {
    const packageEntity: Partial<BasicStoreEntitySupportPackage> = {
      id: '3-nodes-one-in-error',
      package_status: PackageStatus.InProgress,
      nodes_status: [
        {
          node_id: 'firstNodeId',
          package_status: PackageStatus.InError,
        },
        { node_id: 'secondNodeId',
          package_status: PackageStatus.InProgress,
        },
        {
          node_id: 'thirdNodeId',
          package_status: PackageStatus.Ready,
        }],
      nodes_count: 3
    };

    const editResult: EditInput[] = computePackageEntityChanges(packageEntity as BasicStoreEntitySupportPackage, PackageStatus.Ready, 'secondNodeId');
    expect(editResult.length).toBe(2);
    expect(editResult[0].operation).toBe(EditOperation.Replace);
    expect(editResult[0].key).toBe('package_status');
    expect(editResult[0].value[0]).toBe(PackageStatus.InError);

    expect(editResult[1].operation).toBe(EditOperation.Replace);
    expect(editResult[1].key).toBe('nodes_status');

    expect(editResult[1].value.length).toBe(3);
  });
});
