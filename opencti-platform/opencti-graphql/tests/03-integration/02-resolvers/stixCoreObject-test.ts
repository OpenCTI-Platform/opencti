import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import gql from 'graphql-tag';
import Upload from 'graphql-upload/Upload.mjs';
import { findUnknownStixCoreObjects, stixCoreObjectsDistributionByEntity } from '../../../src/domain/stixCoreObject';
import { ADMIN_USER, getUserIdByEmail, testContext, USER_CONNECTOR, USER_DISINFORMATION_ANALYST } from '../../utils/testQuery';
import { queryAsAdminWithSuccess, queryAsUserWithSuccess } from '../../utils/testQueryHelper';
import { elLoadById } from '../../../src/database/engine';
import { deleteFile, fileToReadStream } from '../../../src/database/file-storage';

describe('StixCoreObject resolver standard behavior', () => {
  it('findUnknownStixCoreObjects: should return unknown entities', async () => {
    const md5Hash = '757a71f0fbd6b3d993be2a213338d1f2';
    const malwareName = 'Paradise Ransomware';
    const locationName = 'france';
    const organizationAlias = 'Computer Incident';
    // no values provided
    let unknownValues = await findUnknownStixCoreObjects(testContext, ADMIN_USER, { values: [] });
    expect(unknownValues.length).toEqual(0);
    // some values are representative or hashes of a sco, some are unknown
    unknownValues = await findUnknownStixCoreObjects(testContext, ADMIN_USER, { values: ['unknownValue', locationName, md5Hash] });
    expect(unknownValues.length).toEqual(1);
    expect(unknownValues[0]).toEqual('unknownValue');
    // should be case insensitive
    unknownValues = await findUnknownStixCoreObjects(testContext, ADMIN_USER, { values: ['unknownValue', locationName.toUpperCase(), md5Hash] });
    expect(unknownValues.length).toEqual(1);
    expect(unknownValues[0]).toEqual('unknownValue');
    // some values are aliases
    unknownValues = await findUnknownStixCoreObjects(testContext, ADMIN_USER, { values: ['unknownValue', organizationAlias] });
    expect(unknownValues.length).toEqual(1);
    expect(unknownValues[0]).toEqual('unknownValue');
    // values returned in alphabetical order
    unknownValues = await findUnknownStixCoreObjects(testContext, ADMIN_USER, { values: [malwareName, 'aa', locationName, 'cc', 'bb'], orderBy: 'value', orderMode: 'asc' });
    expect(unknownValues.length).toEqual(3);
    expect(unknownValues).toEqual(['aa', 'bb', 'cc']);
  });
});

describe('stixCoreObjectsDistributionByEntity', () => {
  // Malware Paradise Ransomware (malware--faa5b705-cf44-4e50-8472-29e5fec43c3c)
  // has relationships with attack-patterns and intrusion-set in test data

  it('should return distribution of related entities by entity_type', async () => {
    const malware = await elLoadById(testContext, ADMIN_USER, 'malware--faa5b705-cf44-4e50-8472-29e5fec43c3c');
    expect(malware).toBeDefined();
    const distribution = await stixCoreObjectsDistributionByEntity(testContext, ADMIN_USER, {
      objectId: malware!.internal_id,
      field: 'entity_type',
      operation: 'count',
    });
    expect(distribution).toBeDefined();
    expect(distribution.length).toBeGreaterThan(0);
    const aggregationMap = new Map(distribution.map((i: { label: string; value: number }) => [i.label, i.value]));
    // Malware Paradise Ransomware is related to Attack-Patterns and Intrusion-Set
    expect(aggregationMap.get('Attack-Pattern')).toEqual(2);
    expect(aggregationMap.get('Intrusion-Set')).toEqual(1);
  });

  it('should throw ResourceNotFoundError for unknown objectId', async () => {
    await expect(stixCoreObjectsDistributionByEntity(testContext, ADMIN_USER, {
      objectId: '00000000-0000-0000-0000-000000000000',
      field: 'entity_type',
      operation: 'count',
    })).rejects.toThrow('Specified ids not found or restricted');
  });

  it('should support array of objectIds', async () => {
    const malware = await elLoadById(testContext, ADMIN_USER, 'malware--faa5b705-cf44-4e50-8472-29e5fec43c3c');
    expect(malware).toBeDefined();
    const distribution = await stixCoreObjectsDistributionByEntity(testContext, ADMIN_USER, {
      objectId: [malware!.internal_id],
      field: 'entity_type',
      operation: 'count',
    });
    expect(distribution).toBeDefined();
    expect(distribution.length).toEqual(6);
  });

  it('should support limit option', async () => {
    const malware = await elLoadById(testContext, ADMIN_USER, 'malware--faa5b705-cf44-4e50-8472-29e5fec43c3c');
    expect(malware).toBeDefined();
    const distribution = await stixCoreObjectsDistributionByEntity(testContext, ADMIN_USER, {
      objectId: malware!.internal_id,
      field: 'entity_type',
      operation: 'count',
      limit: 1,
    });
    expect(distribution).toBeDefined();
    expect(distribution.length).toEqual(1);
  });
});

describe('StixCoreObjects export resolvers', () => {
  const EXPORT_CONNECTOR_ID = '4f7b3c1e-2a9d-4e8b-9c6f-1d2e3f4a5b6c';
  const EXPORT_CONNECTOR_NAME = 'TestExportConnector';
  const LIST_EXPORT_CONTEXT = { entity_type: 'Report' };

  const REGISTER_CONNECTOR_QUERY = gql`
    mutation RegisterConnector($input: RegisterConnectorInput) {
      registerConnector(input: $input) {
        id
      }
    }
  `;
  const DELETE_CONNECTOR_QUERY = gql`
    mutation ConnectorDeletionMutation($id: ID!) {
      deleteConnector(id: $id)
    }
  `;
  const CREATE_MALWARE_QUERY = gql`
    mutation MalwareAdd($input: MalwareAddInput!) {
      malwareAdd(input: $input) {
        id
      }
    }
  `;
  const DELETE_STIX_CORE_OBJECT_QUERY = gql`
    mutation StixCoreObjectDelete($id: ID!) {
      stixCoreObjectEdit(id: $id) {
        delete
      }
    }
  `;
  const EXPORTS_ASK_QUERY = gql`
    mutation StixCoreObjectsExportAsk($input: StixCoreObjectsExportAskInput!) {
      stixCoreObjectsExportAsk(input: $input) {
        id
        name
        uploadStatus
      }
    }
  `;
  const EXPORTS_PUSH_QUERY = gql`
    mutation StixCoreObjectsExportPush($entity_type: String!, $file: Upload!, $file_markings: [String]!) {
      stixCoreObjectsExportPush(entity_type: $entity_type, file: $file, file_markings: $file_markings)
    }
  `;
  const EXPORT_ASK_QUERY = gql`
    mutation StixCoreObjectExportAsk($id: ID!, $input: ExportAskInput!) {
      stixCoreObjectEdit(id: $id) {
        exportAsk(input: $input) {
          id
          name
          uploadStatus
        }
      }
    }
  `;
  const EXPORT_PUSH_QUERY = gql`
    mutation StixCoreObjectExportPush($id: ID!, $file: Upload!) {
      stixCoreObjectEdit(id: $id) {
        exportPush(file: $file)
      }
    }
  `;
  const EXPORT_FILES_QUERY = gql`
    query StixCoreObjectsExportFiles($exportContext: ExportContext!, $first: Int) {
      stixCoreObjectsExportFiles(exportContext: $exportContext, first: $first) {
        edges {
          node {
            id
            name
            uploadStatus
            metaData {
              creator_id
            }
          }
        }
      }
    }
  `;

  type ExportFile = { id: string; name: string; uploadStatus: string; metaData?: { creator_id?: string } };
  type ExportContext = { entity_type: string; entity_id?: string };
  const listExportFiles = async (user: typeof USER_CONNECTOR | null, exportContext: ExportContext) => {
    const request = { query: EXPORT_FILES_QUERY, variables: { exportContext, first: 500 } };
    const result = user ? await queryAsUserWithSuccess(user, request) : await queryAsAdminWithSuccess(request);
    return result.data?.stixCoreObjectsExportFiles.edges.map((e: { node: ExportFile }) => e.node) as ExportFile[];
  };
  const toUpload = (fileName: string) => {
    const readStream = fileToReadStream('./tests/data/', 'poisonivy.json', fileName, 'application/json');
    const fileUpload = { ...readStream, encoding: 'utf8' };
    const upload = new Upload();
    upload.promise = new Promise((executor) => {
      executor(fileUpload);
    });
    upload.file = fileUpload;
    return upload;
  };
  // The applicant and bypass users see the export, other users allowed to get exports do not
  const expectOnlyVisibleToApplicant = async (exportContext: ExportContext, predicate: (f: ExportFile) => boolean) => {
    const applicantFiles = await listExportFiles(USER_DISINFORMATION_ANALYST, exportContext);
    expect(applicantFiles.find(predicate)).toBeDefined();
    const otherUserFiles = await listExportFiles(USER_CONNECTOR, exportContext);
    expect(otherUserFiles.find(predicate)).toBeUndefined();
    const adminFiles = await listExportFiles(null, exportContext);
    expect(adminFiles.find(predicate)).toBeDefined();
    return applicantFiles.find(predicate);
  };

  let applicantId: string;
  let malwareId: string;
  const exportFilePaths: string[] = [];

  beforeAll(async () => {
    applicantId = await getUserIdByEmail(USER_DISINFORMATION_ANALYST.email);
    // An alive export connector is required for the export ask to create a work
    await queryAsUserWithSuccess(USER_CONNECTOR, {
      query: REGISTER_CONNECTOR_QUERY,
      variables: {
        input: {
          id: EXPORT_CONNECTOR_ID,
          name: EXPORT_CONNECTOR_NAME,
          type: 'INTERNAL_EXPORT_FILE',
          scope: ['application/json'],
          auto: false,
          only_contextual: false,
        },
      },
    });
    const malware = await queryAsAdminWithSuccess({
      query: CREATE_MALWARE_QUERY,
      variables: { input: { name: 'Malware for export tests' } },
    });
    malwareId = malware.data?.malwareAdd.id;
  });

  afterAll(async () => {
    for (let i = 0; i < exportFilePaths.length; i += 1) {
      await deleteFile(testContext, ADMIN_USER, exportFilePaths[i]);
    }
    if (malwareId) {
      await queryAsAdminWithSuccess({ query: DELETE_STIX_CORE_OBJECT_QUERY, variables: { id: malwareId } });
    }
    // Deleting the connector also deletes its works
    await queryAsAdminWithSuccess({ query: DELETE_CONNECTOR_QUERY, variables: { id: EXPORT_CONNECTOR_ID } });
  });

  describe('list export', () => {
    let exportFileName: string;
    let exportWorkId: string;

    it('stixCoreObjectsExportAsk: should create an export work for the asking user', async () => {
      const result = await queryAsUserWithSuccess(USER_DISINFORMATION_ANALYST, {
        query: EXPORTS_ASK_QUERY,
        variables: {
          input: {
            format: 'application/json',
            exportType: 'simple',
            contentMaxMarkings: [],
            fileMarkings: [],
            exportContext: LIST_EXPORT_CONTEXT,
          },
        },
      });
      const askedFiles = result.data?.stixCoreObjectsExportAsk;
      expect(askedFiles.length).toEqual(1);
      expect(askedFiles[0].name).toContain(`(${EXPORT_CONNECTOR_NAME})_Report_simple.json`);
      expect(askedFiles[0].uploadStatus).not.toEqual('complete');
      exportFileName = askedFiles[0].name;
      exportWorkId = askedFiles[0].id;
    });

    it('stixCoreObjectsExportFiles: should only list the ongoing export to the user who asked for it', async () => {
      await expectOnlyVisibleToApplicant(LIST_EXPORT_CONTEXT, (f) => f.id === exportWorkId);
    });

    it('stixCoreObjectsExportPush: should register the user who asked for the export as file creator', async () => {
      // The export connector pushes the generated file with its own user
      const pushResult = await queryAsUserWithSuccess(USER_CONNECTOR, {
        query: EXPORTS_PUSH_QUERY,
        variables: { entity_type: LIST_EXPORT_CONTEXT.entity_type, file: toUpload(exportFileName), file_markings: [] },
      });
      expect(pushResult.data?.stixCoreObjectsExportPush).toEqual(true);
      exportFilePaths.push(`export/${LIST_EXPORT_CONTEXT.entity_type}/${exportFileName}`);

      const isGeneratedFile = (f: ExportFile) => f.name === exportFileName && f.uploadStatus === 'complete';
      const applicantFile = await expectOnlyVisibleToApplicant(LIST_EXPORT_CONTEXT, isGeneratedFile);
      expect(applicantFile?.metaData?.creator_id).toEqual(applicantId);
    });
  });

  describe('entity export', () => {
    let exportContext: ExportContext;
    let exportFileName: string;
    let exportWorkId: string;

    it('exportAsk: should create an export work for the asking user', async () => {
      exportContext = { entity_type: 'Malware', entity_id: malwareId };
      const result = await queryAsUserWithSuccess(USER_DISINFORMATION_ANALYST, {
        query: EXPORT_ASK_QUERY,
        variables: {
          id: malwareId,
          input: { format: 'application/json', exportType: 'simple', contentMaxMarkings: [], fileMarkings: [] },
        },
      });
      const askedFiles = result.data?.stixCoreObjectEdit.exportAsk;
      expect(askedFiles.length).toEqual(1);
      expect(askedFiles[0].name).toContain(`(${EXPORT_CONNECTOR_NAME})_Malware-Malware for export tests_simple.json`);
      expect(askedFiles[0].uploadStatus).not.toEqual('complete');
      exportFileName = askedFiles[0].name;
      exportWorkId = askedFiles[0].id;
    });

    it('stixCoreObjectsExportFiles: should only list the ongoing entity export to the user who asked for it', async () => {
      await expectOnlyVisibleToApplicant(exportContext, (f) => f.id === exportWorkId);
    });

    it('exportPush: should register the user who asked for the export as file creator', async () => {
      // The export connector pushes the generated file with its own user
      const pushResult = await queryAsUserWithSuccess(USER_CONNECTOR, {
        query: EXPORT_PUSH_QUERY,
        variables: { id: malwareId, file: toUpload(exportFileName) },
      });
      expect(pushResult.data?.stixCoreObjectEdit.exportPush).toEqual(true);
      exportFilePaths.push(`export/Malware/${malwareId}/${exportFileName}`);

      const isGeneratedFile = (f: ExportFile) => f.name === exportFileName && f.uploadStatus === 'complete';
      const applicantFile = await expectOnlyVisibleToApplicant(exportContext, isGeneratedFile);
      expect(applicantFile?.metaData?.creator_id).toEqual(applicantId);
    });
  });
});
