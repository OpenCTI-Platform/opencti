import { describe, it, expect } from 'vitest';
import { commitLocalUpdate, commitMutation, ConnectionHandler, GraphQLTaggedNode } from 'relay-runtime';
import { createMockEnvironment, MockPayloadGenerator } from 'relay-test-utils';
import FileManagerExportMutation from '@components/common/files/__generated__/FileManagerExportMutation.graphql';
import StixCoreObjectFilesAndHistoryExportMutation from '@components/common/stix_core_objects/__generated__/StixCoreObjectFilesAndHistoryExportMutation.graphql';
import { insertOngoingExports } from './store';

const ENTITY_ID = 'report--1';
const input = {
  format: 'application/json',
  exportType: 'simple',
  contentMaxMarkings: [],
  fileMarkings: [],
};

const setupEnvironment = ({ withFilesList }: { withFilesList: boolean }) => {
  const environment = createMockEnvironment();
  commitLocalUpdate(environment, (store) => {
    const entity = store.create(ENTITY_ID, 'Report');
    if (withFilesList) {
      const conn = store.create(`client:${ENTITY_ID}:__Pagination_exportFiles_connection`, 'FileConnection');
      conn.setLinkedRecords([], 'edges');
      entity.setLinkedRecord(conn, '__Pagination_exportFiles_connection');
    }
  });
  return environment;
};

const askExport = (
  environment: ReturnType<typeof createMockEnvironment>,
  mutation: GraphQLTaggedNode,
  rootField: string,
) => {
  commitMutation(environment, {
    mutation,
    variables: { id: ENTITY_ID, input },
    updater: (store) => insertOngoingExports(store, ENTITY_ID, rootField, input),
  });
  environment.mock.resolveMostRecentOperation((operation) => MockPayloadGenerator.generate(operation, {
    File: () => ({ id: 'export-file-1', name: 'export.json', uploadStatus: 'progress' }),
  }));
};

const readExportFiles = (environment: ReturnType<typeof createMockEnvironment>) => {
  let files: { id: unknown; uploadStatus: unknown }[] | null = null;
  commitLocalUpdate(environment, (store) => {
    const entity = store.get(ENTITY_ID);
    const conn = entity ? ConnectionHandler.getConnection(entity, 'Pagination_exportFiles') : null;
    files = conn
      ? (conn.getLinkedRecords('edges') ?? []).map((edge) => {
          const node = edge?.getLinkedRecord('node');
          return { id: node?.getValue('id'), uploadStatus: node?.getValue('uploadStatus') };
        })
      : null;
  });
  return files;
};

describe('Function: insertOngoingExports()', () => {
  it.each([
    ['stixCoreObjectEdit', FileManagerExportMutation],
    ['stixDomainObjectEdit', StixCoreObjectFilesAndHistoryExportMutation],
  ])('should insert the ongoing export in the files list from %s', (rootField, mutation) => {
    const environment = setupEnvironment({ withFilesList: true });
    askExport(environment, mutation, rootField);
    expect(readExportFiles(environment)).toEqual([{ id: 'export-file-1', uploadStatus: 'progress' }]);
  });

  it('should do nothing when the files list is not mounted', () => {
    const environment = setupEnvironment({ withFilesList: false });
    expect(() => askExport(environment, FileManagerExportMutation, 'stixCoreObjectEdit')).not.toThrow();
    expect(readExportFiles(environment)).toBeNull();
  });
});
