import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import gql from 'graphql-tag';
import Upload from 'graphql-upload/Upload.mjs';
import { findUnknownStixCoreObjects, stixCoreObjectsDistributionByEntity } from '../../../src/domain/stixCoreObject';
import { ADMIN_USER, getUserIdByEmail, testContext, USER_CONNECTOR, USER_DISINFORMATION_ANALYST, USER_PARTICIPATE } from '../../utils/testQuery';
import { queryAsAdminWithError, queryAsAdminWithSuccess, queryAsUserWithSuccess } from '../../utils/testQueryHelper';
import { elLoadById } from '../../../src/database/engine';
import { MARKING_TLP_AMBER } from '../../../src/schema/identifier';
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

  it('should keep the order of a distribution out of its aggregation', async () => {
    // The order of the distribution APIs only sorts their result: any value must reach Elasticsearch unchanged
    const DISTRIBUTION_QUERY = gql`
      query StixCoreObjectsDistributionOrder($order: String) {
        stixCoreObjectsDistribution(field: "entity_type", operation: count, types: ["Stix-Domain-Object"], limit: 3, order: $order) {
          label
          value
        }
      }
    `;
    const withoutOrder = await queryAsAdminWithSuccess({ query: DISTRIBUTION_QUERY, variables: {} });
    const withUnknownOrder = await queryAsAdminWithSuccess({ query: DISTRIBUTION_QUERY, variables: { order: 'descending' } });
    expect(withoutOrder.data?.stixCoreObjectsDistribution.length).toEqual(3);
    expect(withUnknownOrder.data?.stixCoreObjectsDistribution).toEqual(withoutOrder.data?.stixCoreObjectsDistribution);
  });
});

describe('stixCoreObjectsTimeSeriesBreakdown', () => {
  const LABEL_ADD_QUERY = gql`
    mutation LabelAdd($input: LabelAddInput!) {
      labelAdd(input: $input) {
        id
      }
    }
  `;
  const LABEL_DELETE_QUERY = gql`
    mutation LabelDelete($id: ID!) {
      labelEdit(id: $id) {
        delete
      }
    }
  `;
  const ORGANIZATION_ADD_QUERY = gql`
    mutation OrganizationAdd($input: OrganizationAddInput!) {
      organizationAdd(input: $input) {
        id
      }
    }
  `;
  const ORGANIZATION_DELETE_QUERY = gql`
    mutation OrganizationDelete($id: ID!) {
      organizationDelete(id: $id)
    }
  `;
  const REPORT_ADD_QUERY = gql`
    mutation ReportAdd($input: ReportAddInput!) {
      reportAdd(input: $input) {
        id
      }
    }
  `;
  const REPORT_DELETE_QUERY = gql`
    mutation ReportDelete($id: ID!) {
      reportEdit(id: $id) {
        delete
      }
    }
  `;
  const BREAKDOWN_QUERY = gql`
    query StixCoreObjectsTimeSeriesBreakdown(
      $field: String!
      $dateAttribute: String
      $startDate: DateTime!
      $endDate: DateTime
      $interval: String!
      $limit: Int
      $order: OrderingMode
      $includeOther: Boolean
      $types: [String]
      $filters: FilterGroup
    ) {
      stixCoreObjectsTimeSeriesBreakdown(
        field: $field
        dateAttribute: $dateAttribute
        startDate: $startDate
        endDate: $endDate
        interval: $interval
        limit: $limit
        order: $order
        includeOther: $includeOther
        types: $types
        filters: $filters
      ) {
        truncated
        dates
        series {
          label
          value
          isOther
          entity {
            ... on Label {
              value
            }
            ... on Organization {
              name
            }
          }
          values
        }
      }
    }
  `;
  type Serie = { label: string; value: number; isOther: boolean; entity: { value?: string; name?: string } | null; values: number[] };
  const LABELS = { a: 'bkd-int-a', b: 'bkd-int-b', c: 'bkd-int-c' };
  // Reports (label, creation date, marking): a=3, b=2, c=1 and one report without label, over January to March 2021.
  // Their author, the report of b of February and the report without label are amber: a user of the green group
  // reads 5 reports out of 7 (a=3, b=1, c=1, from January to March 2, 1 and 2), and not their author.
  const REPORTS: { label: keyof typeof LABELS | null; created: string; marking: string | null }[] = [
    { label: 'a', created: '2021-01-10T12:00:00.000Z', marking: null },
    { label: 'a', created: '2021-01-20T12:00:00.000Z', marking: null },
    { label: 'a', created: '2021-02-10T12:00:00.000Z', marking: null },
    { label: 'b', created: '2021-02-20T12:00:00.000Z', marking: MARKING_TLP_AMBER },
    { label: 'b', created: '2021-03-10T12:00:00.000Z', marking: null },
    { label: 'c', created: '2021-03-20T12:00:00.000Z', marking: null },
    { label: null, created: '2021-01-25T12:00:00.000Z', marking: MARKING_TLP_AMBER },
  ];
  let organizationId: string;
  const labelIds: Record<string, string> = {};
  const reportIds: string[] = [];

  type Breakdown = { truncated: boolean; dates: (Date | string)[]; series: Serie[] };
  const breakdownRequest = (variables: Record<string, unknown>) => ({
    query: BREAKDOWN_QUERY,
    variables: {
      dateAttribute: 'created',
      startDate: '2021-01-01T00:00:00.000Z',
      endDate: '2021-03-31T23:59:59.999Z',
      interval: 'month',
      types: ['Report'],
      // Isolate the reports of this test from the ones of the other tests
      filters: { mode: 'and', filters: [{ key: ['createdBy'], values: [organizationId] }], filterGroups: [] },
      ...variables,
    },
  });
  const breakdown = async (variables: Record<string, unknown>) => {
    const result = await queryAsAdminWithSuccess(breakdownRequest(variables));
    // DateTime values are Date objects when the query runs in process, ISO strings over HTTP
    return result.data?.stixCoreObjectsTimeSeriesBreakdown as Breakdown;
  };
  // As a user of the green group, who reads neither the amber reports nor their amber author
  const breakdownAsGreenUser = async (variables: Record<string, unknown>) => {
    const result = await queryAsUserWithSuccess(USER_PARTICIPATE, breakdownRequest(variables));
    return result.data?.stixCoreObjectsTimeSeriesBreakdown as Breakdown;
  };
  const sumOf = (serie: Serie) => serie.values.reduce((total, value) => total + value, 0);
  const expectBreakdownError = (variables: Record<string, unknown>, message: string) => {
    const request = {
      query: BREAKDOWN_QUERY,
      variables: { dateAttribute: 'created', startDate: '2021-01-01T00:00:00.000Z', interval: 'month', types: ['Report'], ...variables },
    };
    return queryAsAdminWithError(request, message, 'FUNCTIONAL_ERROR');
  };

  beforeAll(async () => {
    const organization = await queryAsAdminWithSuccess({
      query: ORGANIZATION_ADD_QUERY,
      variables: { input: { name: 'bkd-int-author', objectMarking: [MARKING_TLP_AMBER] } },
    });
    organizationId = organization.data?.organizationAdd.id;
    for (const [key, value] of Object.entries(LABELS)) {
      const label = await queryAsAdminWithSuccess({ query: LABEL_ADD_QUERY, variables: { input: { value } } });
      labelIds[key] = label.data?.labelAdd.id;
    }
    for (let i = 0; i < REPORTS.length; i += 1) {
      const { label, created, marking } = REPORTS[i];
      const report = await queryAsAdminWithSuccess({
        query: REPORT_ADD_QUERY,
        variables: {
          input: {
            name: `bkd-int-report-${i}`,
            published: created,
            created,
            report_types: ['threat-report'],
            createdBy: organizationId,
            objectLabel: label ? [labelIds[label]] : [],
            objectMarking: marking ? [marking] : [],
          },
        },
      });
      reportIds.push(report.data?.reportAdd.id);
    }
  });

  afterAll(async () => {
    for (let i = 0; i < reportIds.length; i += 1) {
      await queryAsAdminWithSuccess({ query: REPORT_DELETE_QUERY, variables: { id: reportIds[i] } });
    }
    for (const id of Object.values(labelIds)) {
      await queryAsAdminWithSuccess({ query: LABEL_DELETE_QUERY, variables: { id } });
    }
    if (organizationId) {
      await queryAsAdminWithSuccess({ query: ORGANIZATION_DELETE_QUERY, variables: { id: organizationId } });
    }
  });

  it('should break down by label in descending order', async () => {
    const { truncated, dates, series } = await breakdown({ field: 'objectLabel', order: 'desc', limit: 2 });
    expect(series.map((s) => s.entity?.value)).toEqual([LABELS.a, LABELS.b]);
    expect(series.map((s) => s.value)).toEqual([3, 2]);
    expect(series.map((s) => s.isOther)).toEqual([false, false]);
    // The label c is left out by the limit
    expect(truncated).toEqual(true);
    series.forEach((serie) => expect(sumOf(serie)).toEqual(serie.value));
    // One point per month, from January to March, on dates shared by every serie
    expect(dates.map((date) => new Date(date).toISOString())).toEqual(['2021-01-01T00:00:00.000Z', '2021-02-01T00:00:00.000Z', '2021-03-01T00:00:00.000Z']);
    expect(series[0].values).toEqual([2, 1, 0]);
    expect(series[1].values).toEqual([0, 1, 1]);
    // With a limit above the number of labels, nothing is left out and the unlabeled report is not a serie
    const all = await breakdown({ field: 'objectLabel', order: 'desc', limit: 10 });
    expect(all.truncated).toEqual(false);
    expect(all.series.map((s) => s.entity?.value)).toEqual([LABELS.a, LABELS.b, LABELS.c]);
  });

  it('should break down with one filter per value when there are many values for the series kept', async () => {
    // 3 labels for 1 series: the histogram uses one filter per value instead of a restricted terms
    const { truncated, series } = await breakdown({ field: 'objectLabel', order: 'desc', limit: 1, includeOther: true });
    expect(truncated).toEqual(true);
    expect(series.map((s) => s.entity?.value ?? s.label)).toEqual([LABELS.a, 'Other']);
    expect(series[0].values).toEqual([2, 1, 0]);
    expect(series[0].value).toEqual(3);
    // Other: the reports of the labels b and c, and the unlabeled report
    expect(series[1].values).toEqual([1, 1, 2]);
    expect(series[1].value).toEqual(4);
  });

  it('should break down by label in ascending order', async () => {
    const { truncated, series } = await breakdown({ field: 'objectLabel', order: 'asc', limit: 2 });
    expect(series.map((s) => s.entity?.value)).toEqual([LABELS.c, LABELS.b]);
    expect(series.map((s) => s.value)).toEqual([1, 2]);
    expect(series.map((s) => s.isOther)).toEqual([false, false]);
    expect(truncated).toEqual(true);
    series.forEach((serie) => expect(sumOf(serie)).toEqual(serie.value));
  });

  it('should add the Other serie for the entities outside of the selected series', async () => {
    // desc: Other counts the report of the label c and the unlabeled report
    const desc = await breakdown({ field: 'objectLabel', order: 'desc', limit: 2, includeOther: true });
    expect(desc.series.map((s) => s.isOther)).toEqual([false, false, true]);
    expect(desc.series.slice(0, 2).map((s) => s.entity?.value)).toEqual([LABELS.a, LABELS.b]);
    const descOther = desc.series[2];
    expect(descOther.label).toEqual('Other');
    expect(descOther.entity).toBeNull();
    expect(descOther.value).toEqual(2);
    expect(sumOf(descOther)).toEqual(2);
    expect(descOther.values).toEqual([1, 0, 1]);
    // asc: Other counts the reports of the label a and the unlabeled report
    const asc = await breakdown({ field: 'objectLabel', order: 'asc', limit: 2, includeOther: true });
    expect(asc.series.map((s) => s.isOther)).toEqual([false, false, true]);
    expect(asc.series.slice(0, 2).map((s) => s.entity?.value)).toEqual([LABELS.c, LABELS.b]);
    expect(asc.series[2].value).toEqual(4);
    expect(sumOf(asc.series[2])).toEqual(4);
  });

  it('should break down by a scalar field', async () => {
    const byType = await breakdown({ field: 'entity_type' });
    expect(byType.truncated).toEqual(false);
    expect(byType.series.map((s) => [s.label, s.value, s.entity])).toEqual([['Report', REPORTS.length, null]]);
    expect(sumOf(byType.series[0])).toEqual(REPORTS.length);
    const byReportType = await breakdown({ field: 'report_types' });
    expect(byReportType.series.map((s) => [s.label, s.value])).toEqual([['threat-report', REPORTS.length]]);
  });

  it('should not count the entities above the markings of the user, neither in the series nor in Other', async () => {
    // The top label is the same for both: Other loses the amber reports of February (b) and January (no label)
    const top = await breakdownAsGreenUser({ field: 'objectLabel', order: 'desc', limit: 1, includeOther: true });
    expect(top.truncated).toEqual(true);
    expect(top.series.map((s) => [s.entity?.value ?? s.label, s.value, s.values])).toEqual([
      [LABELS.a, 3, [2, 1, 0]],
      // [1, 1, 2] for the admin
      ['Other', 2, [0, 0, 2]],
    ]);
    // The series of b loses its amber report; b and c then tie, so the series are compared by label
    const all = await breakdownAsGreenUser({ field: 'objectLabel', order: 'desc', limit: 10, includeOther: true });
    expect(all.truncated).toEqual(false);
    expect(Object.fromEntries(all.series.map((s) => [s.entity?.value ?? s.label, [s.value, s.values]]))).toEqual({
      [LABELS.a]: [3, [2, 1, 0]],
      [LABELS.b]: [1, [0, 0, 1]],
      [LABELS.c]: [1, [0, 0, 1]],
      // The only report without any of the labels is amber
      Other: [0, [0, 0, 0]],
    });
    const byType = await breakdownAsGreenUser({ field: 'entity_type' });
    expect(byType.series.map((s) => [s.label, s.value, s.values])).toEqual([['Report', 5, [2, 1, 2]]]);
  });

  it('should break down by an author the user cannot read as a restricted entity', async () => {
    const asAdmin = await breakdown({ field: 'createdBy' });
    expect(asAdmin.series.map((s) => [s.label, s.entity?.name, s.value, s.values])).toEqual([[organizationId, 'bkd-int-author', 7, [3, 2, 2]]]);
    // The reports the user reads are counted, under the id of their author, which is restricted
    const asGreenUser = await breakdownAsGreenUser({ field: 'createdBy' });
    expect(asGreenUser.series.map((s) => [s.label, s.entity?.name, s.value, s.values])).toEqual([[organizationId, 'Restricted', 5, [2, 1, 2]]]);
  });

  it('should refuse a field that cannot be broken down', async () => {
    const message = 'Time series breakdown does not support this field for these entity types';
    await expectBreakdownError({ field: 'objects' }, message);
    await expectBreakdownError({ field: 'externalReferences' }, message);
  });

  it('should refuse an invalid limit', async () => {
    const message = 'Time series breakdown limit must be an integer between 1 and the maximum';
    await expectBreakdownError({ field: 'objectLabel', limit: 0 }, message);
    await expectBreakdownError({ field: 'objectLabel', limit: 51 }, message);
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
