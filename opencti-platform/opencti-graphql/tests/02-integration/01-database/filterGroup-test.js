import { describe, expect, it } from 'vitest';
import gql from 'graphql-tag';
import { ADMIN_USER, queryAsAdmin, testContext } from '../../utils/testQuery';
import { addAllowedMarkingDefinition } from '../../../src/domain/markingDefinition';
import { distributionRelations } from '../../../src/database/middleware';
import { ENTITY_TYPE_MARKING_DEFINITION } from '../../../src/schema/stixMetaObject';
import { RELATION_OBJECT_MARKING } from '../../../src/schema/stixRefRelationship';
import { ABSTRACT_INTERNAL_OBJECT, ABSTRACT_STIX_CORE_OBJECT, ENTITY_TYPE_CONTAINER, ENTITY_TYPE_LOCATION, ID_INTERNAL } from '../../../src/schema/general';
import { ENTITY_TYPE_CONTAINER_REPORT, ENTITY_TYPE_INTRUSION_SET, ENTITY_TYPE_MALWARE } from '../../../src/schema/stixDomainObject';
import {
  COMPUTED_RELIABILITY_FILTER,
  IDS_FILTER,
  INSTANCE_RELATION_FILTER,
  INSTANCE_RELATION_TYPES_FILTER,
  RELATION_FROM_TYPES_FILTER,
  RELATION_TO_TYPES_FILTER,
  SOURCE_RELIABILITY_FILTER
} from '../../../src/utils/filtering/filtering-constants';
import { storeLoadById } from '../../../src/database/middleware-loader';

// test queries involving dynamic filters

const REPORT_LIST_QUERY = gql`
    query reports(
        $filters: FilterGroup
    ) {
        reports(
            filters: $filters
        ) {
            edges {
                node {
                    id
                    name
                    description
                    published
                    report_types
                    confidence
                    objectMarking {
                      id
                      standard_id
                      definition
                    }
                }
            }
        }
    }
`;

const LIST_QUERY = gql`
    query globalSearch(
        $filters: FilterGroup
    ) {
        globalSearch(
            filters: $filters
        ) {
            edges {
                node {
                    id
                    entity_type
                }
            }
        }
    }
`;

const RELATIONSHIP_QUERY = gql`
    query stixCoreRelationships(
        $filters: FilterGroup
    ) {
        stixCoreRelationships(filters: $filters) {
            edges {
                node {
                    id
                    relationship_type
                    start_time
                    stop_time
                }
            }
        }
    }
`;

const READ_REPORT_QUERY = gql`
    query report($id: String!) {
        report(id: $id) {
            id
            standard_id
            name
        }
    }
`;

const READ_MARKING_QUERY = gql`
    query markingDefinition($id: String!) {
        markingDefinition(id: $id) {
            id
            standard_id
        }
    }
`;

describe('Complex filters combinations for elastic queries', () => {
  let report1InternalId;
  let report2InternalId;
  let report3InternalId;
  let report4InternalId;
  const report1StixId = 'report--994491f0-f114-4e41-bcf0-3288c0324f01';
  const report2StixId = 'report--994491f0-f114-4e41-bcf0-3288c0324f02';
  const report3StixId = 'report--994491f0-f114-4e41-bcf0-3288c0324f03';
  const report4StixId = 'report--994491f0-f114-4e41-bcf0-3288c0324f04';
  let marking1StixId;
  let marking1Id;
  let marking2StixId;
  let marking2Id;
  it('should testing environment created', async () => {
    const CREATE_QUERY = gql`
        mutation ReportAdd($input: ReportAddInput!) {
            reportAdd(input: $input) {
                id
                standard_id
                name
            }
        }
    `;
    // Create a marking
    const marking1Input = {
      definition_type: 'TLP',
      definition: 'TLP:NEW',
      x_opencti_order: 1,
    };
    const marking2Input = {
      definition_type: 'TEST',
      definition: 'TEST:2',
      x_opencti_order: 2,
    };
    const marking1 = await addAllowedMarkingDefinition(testContext, ADMIN_USER, marking1Input);
    marking1StixId = marking1.standard_id;
    marking1Id = marking1.id;
    const marking2 = await addAllowedMarkingDefinition(testContext, ADMIN_USER, marking2Input);
    marking2StixId = marking2.standard_id;
    marking2Id = marking2.id;
    // Create the reports
    const REPORT1 = {
      input: {
        name: 'Report1',
        stix_id: report1StixId,
        description: 'Report1 description',
        published: '2023-09-26T00:47:35.000Z',
        objectMarking: [marking1StixId, marking2StixId],
        report_types: ['threat-report'],
        confidence: 10,
      },
    };
    const REPORT2 = {
      input: {
        name: 'Report2',
        stix_id: report2StixId,
        description: 'Report2 description',
        lang: 'Report1',
        published: '2023-09-15T00:51:35.000Z',
        objectMarking: [marking2StixId],
        report_types: ['threat-report', 'internal-report'],
        confidence: 20,
      },
    };
    const REPORT3 = {
      input: {
        name: 'Report3',
        stix_id: report3StixId,
        published: '2021-01-10T22:00:00.000Z',
        report_types: ['internal-report'],
        confidence: 30,
      },
    };
    const REPORT4 = {
      input: {
        name: 'Report4',
        description: '', // empty string
        stix_id: report4StixId,
        published: '2023-09-15T00:51:35.000Z',
        objectMarking: [marking2StixId],
        confidence: 40,
      },
    };
    const report1 = await queryAsAdmin({
      query: CREATE_QUERY,
      variables: REPORT1,
    });
    const report2 = await queryAsAdmin({
      query: CREATE_QUERY,
      variables: REPORT2,
    });
    const report3 = await queryAsAdmin({
      query: CREATE_QUERY,
      variables: REPORT3,
    });
    const report4 = await queryAsAdmin({
      query: CREATE_QUERY,
      variables: REPORT4,
    });
    expect(report1).not.toBeNull();
    expect(report1.data.reportAdd).not.toBeNull();
    expect(report1.data.reportAdd.name).toEqual('Report1');
    expect(report2).not.toBeNull();
    expect(report2.data.reportAdd).not.toBeNull();
    expect(report2.data.reportAdd.name).toEqual('Report2');
    expect(report3).not.toBeNull();
    expect(report3.data.reportAdd).not.toBeNull();
    expect(report3.data.reportAdd.name).toEqual('Report3');
    expect(report4).not.toBeNull();
    expect(report4.data.reportAdd).not.toBeNull();
    expect(report4.data.reportAdd.name).toEqual('Report4');
    report1InternalId = report1.data.reportAdd.id;
    report2InternalId = report2.data.reportAdd.id;
    report3InternalId = report3.data.reportAdd.id;
    report4InternalId = report4.data.reportAdd.id;
  });
  it('should list entities according to filters: filters with unexisting values', async () => {
    const queryResult = await queryAsAdmin({
      query: REPORT_LIST_QUERY,
      variables: {
        first: 10,
        filters: {
          mode: 'and',
          filters: [{
            key: 'report_types',
            operator: 'eq',
            values: ['unexistingType'],
            mode: 'or',
          }],
          filterGroups: [],
        },
      }
    });
    expect(queryResult.data.reports.edges.length).toEqual(0);
  });
  it('should list entities according to filters: no filters', async () => {
    let queryResult = await queryAsAdmin({
      query: REPORT_LIST_QUERY,
      variables: {
        first: 10,
        filters: {
          mode: 'and',
          filters: [],
          filterGroups: [],
        },
      }
    });
    expect(queryResult.data.reports.edges.length).toEqual(5); // the 4 reports created + the report in DATA-TEST-STIX2_v2.json
    queryResult = await queryAsAdmin({ query: REPORT_LIST_QUERY });
    expect(queryResult.data.reports.edges.length).toEqual(5);
  });
  it('should list entities according to filters: one filter', async () => {
    const queryResult = await queryAsAdmin({
      query: REPORT_LIST_QUERY,
      variables: {
        first: 10,
        filters: {
          mode: 'and',
          filters: [
            {
              key: 'report_types',
              operator: 'eq',
              values: ['threat-report'],
              mode: 'or',
            }
          ],
          filterGroups: [],
        },
      }
    });
    expect(queryResult.data.reports.edges.length).toEqual(3); // the reports created + the report in DATA-TEST-STIX2_v2.json
  });
  it('should list entities according to filters: filters with different operators', async () => {
    // (report_types = threat-report) AND (report_types != internal-report)
    const queryResult = await queryAsAdmin({
      query: REPORT_LIST_QUERY,
      variables: {
        first: 10,
        filters: {
          mode: 'and',
          filters: [
            {
              key: 'report_types',
              operator: 'eq',
              values: ['threat-report'],
              mode: 'or',
            },
            {
              key: 'report_types',
              operator: 'not_eq',
              values: ['internal-report'],
              mode: 'or',
            }
          ],
          filterGroups: [],
        },
      }
    });
    expect(queryResult.data.reports.edges.length).toEqual(2); // report1 and the report in DATA-TEST-STIX2_v2.json
    expect(queryResult.data.reports.edges.map((n) => n.node.name)).includes('Report1').toBeTruthy();
    expect(queryResult.data.reports.edges.map((n) => n.node.name)).includes('A demo report for testing purposes').toBeTruthy();
  });
  it('should list entities according to filters: filters with different modes for the main filter group', async () => {
    // (published after 20/09/2023) OR (published before 30/12/2021)
    let queryResult = await queryAsAdmin({
      query: REPORT_LIST_QUERY,
      variables: {
        first: 10,
        filters: {
          mode: 'or',
          filters: [
            {
              key: 'published',
              operator: 'gt',
              values: ['2023-09-20T00:47:35.000Z'],
              mode: 'or',
            },
            {
              key: 'published',
              operator: 'lt',
              values: ['2021-12-30T00:47:35.000Z'],
              mode: 'or',
            }
          ],
          filterGroups: [],
        },
      }
    });
    expect(queryResult.data.reports.edges.length).toEqual(3); // report1 and report3 and report in DATA-TEST-STIX2_v2.json
    expect(queryResult.data.reports.edges.map((n) => n.node.name).includes('Report1')).toBeTruthy();
    expect(queryResult.data.reports.edges.map((n) => n.node.name).includes('Report3')).toBeTruthy();
    expect(queryResult.data.reports.edges.map((n) => n.node.name)).includes('A demo report for testing purposes').toBeTruthy();
    // (published after 20/09/2023) AND (published before 30/12/2021)
    queryResult = await queryAsAdmin({
      query: REPORT_LIST_QUERY,
      variables: {
        first: 10,
        filters: {
          mode: 'and',
          filters: [
            {
              key: 'published',
              operator: 'gt',
              values: ['2023-09-20T00:47:35.000Z'],
              mode: 'or',
            },
            {
              key: 'published',
              operator: 'lt',
              values: ['2021-12-30T00:47:35.000Z'],
              mode: 'or',
            }
          ],
          filterGroups: [],
        },
      }
    });
    expect(queryResult.data.reports.edges.length).toEqual(0);
  });
  it('should list entities according to filters: filters with different modes between the values of a filter', async () => {
    // (report_types = internal-report OR threat-report)
    let queryResult = await queryAsAdmin({
      query: REPORT_LIST_QUERY,
      variables: {
        first: 10,
        filters: {
          mode: 'and',
          filters: [
            {
              key: 'report_types',
              operator: 'eq',
              values: ['internal-report', 'threat-report'],
              mode: 'or',
            }
          ],
          filterGroups: [],
        },
      }
    });
    expect(queryResult.data.reports.edges.length).toEqual(4); // 3 of the reports created + the report in DATA-TEST-STIX2_v2.json
    // (report_types = internal-report AND threat-report)
    queryResult = await queryAsAdmin({
      query: REPORT_LIST_QUERY,
      variables: {
        first: 10,
        filters: {
          mode: 'and',
          filters: [
            {
              key: 'report_types',
              operator: 'eq',
              values: ['internal-report', 'threat-report'],
              mode: 'and',
            }
          ],
          filterGroups: [],
        },
      }
    });
    expect(queryResult.data.reports.edges.length).toEqual(1);
    expect(queryResult.data.reports.edges[0].node.name).toEqual('Report2');
  });
  it('should list entities according to filters: filters and filter groups', async () => {
    // (report_types = threat-report AND published before 30/12/2021)
    let queryResult = await queryAsAdmin({
      query: REPORT_LIST_QUERY,
      variables: {
        first: 10,
        filters: {
          mode: 'and',
          filters: [
            {
              key: 'report_types',
              operator: 'eq',
              values: ['threat-report'],
              mode: 'or',
            },
            {
              key: 'published',
              operator: 'lt',
              values: ['2023-09-20T00:47:35.000Z'],
              mode: 'or',
            }
          ],
          filterGroups: [],
        },
      }
    });
    expect(queryResult.data.reports.edges.length).toEqual(2);
    expect(queryResult.data.reports.edges.map((n) => n.node.name)).includes('Report2').toBeTruthy();
    expect(queryResult.data.reports.edges.map((n) => n.node.name)).includes('A demo report for testing purposes').toBeTruthy();
    //  (published before 20/09/2023) AND (report_types = threat-report OR objects malwareXX)
    queryResult = await queryAsAdmin({
      query: REPORT_LIST_QUERY,
      variables: {
        first: 10,
        filters: {
          mode: 'and',
          filters: [
            {
              key: 'published',
              operator: 'lt',
              values: ['2023-09-20T00:47:35.000Z'],
              mode: 'or',
            }
          ],
          filterGroups: [
            {
              mode: 'or',
              filters: [
                {
                  key: 'report_types',
                  operator: 'eq',
                  values: ['threat-report'],
                  mode: 'or',
                },
                {
                  key: 'objects',
                  operator: 'eq',
                  values: ['malware--21c45dbe-54ec-5bb7-b8cd-9f27cc518714'],
                  mode: 'or',
                }
              ],
              filterGroups: [],
            },
          ],
        },
      }
    });
    expect(queryResult.data.reports.edges.length).toEqual(2);
    expect(queryResult.data.reports.edges.map((n) => n.node.name)).includes('Report2').toBeTruthy();
    expect(queryResult.data.reports.edges.map((n) => n.node.name)).includes('A demo report for testing purposes').toBeTruthy();
    // (marking = marking1 AND marking2) OR (report_types = threat-report AND published before 20/09/2023)
    queryResult = await queryAsAdmin({
      query: REPORT_LIST_QUERY,
      variables: {
        first: 10,
        filters: {
          mode: 'or',
          filters: [
            {
              key: 'objectMarking',
              operator: 'eq',
              values: [marking1Id, marking2Id],
              mode: 'and',
            }
          ],
          filterGroups: [
            {
              mode: 'and',
              filters: [
                {
                  key: 'report_types',
                  operator: 'eq',
                  values: ['threat-report'],
                  mode: 'or',
                },
                {
                  key: 'published',
                  operator: 'lt',
                  values: ['2023-09-20T00:47:35.000Z'],
                  mode: 'or',
                }
              ],
              filterGroups: [],
            },
          ],
        },
      }
    });
    expect(queryResult.data.reports.edges.length).toEqual(3);
    expect(queryResult.data.reports.edges.map((n) => n.node.name).includes('Report1')).toBeTruthy();
    expect(queryResult.data.reports.edges.map((n) => n.node.name).includes('Report2')).toBeTruthy();
    expect(queryResult.data.reports.edges.map((n) => n.node.name)).includes('A demo report for testing purposes').toBeTruthy();
  });
  it('should list entities according to filters: complex filter combination with groups and filters imbrication', async () => {
    // (confidence > 50)
    // OR
    //    [(confidence > 15)
    //    AND
    //        [(report_types != internal-report)
    //        OR
    //            (report_types = (internal-report OR threat-report)
    //            AND
    //            marking = marking2
    //            )
    //        ]
    //    ]
    const queryResult = await queryAsAdmin({
      query: REPORT_LIST_QUERY,
      variables: {
        first: 10,
        filters: {
          mode: 'or',
          filters: [
            {
              key: 'confidence',
              operator: 'gt',
              values: ['50'],
              mode: 'or',
            }
          ],
          filterGroups: [
            {
              mode: 'and',
              filters: [
                {
                  key: 'confidence',
                  operator: 'gt',
                  values: ['15'],
                  mode: 'or',
                }
              ],
              filterGroups: [
                {
                  mode: 'or',
                  filters: [
                    {
                      key: 'report_types',
                      operator: 'not_eq',
                      values: ['internal-report'],
                      mode: 'or',
                    }
                  ],
                  filterGroups: [{
                    mode: 'and',
                    filters: [
                      {
                        key: 'report_types',
                        operator: 'eq',
                        values: ['internal-report', 'threat-report'],
                        mode: 'or',
                      },
                      {
                        key: 'objectMarking',
                        operator: 'eq',
                        values: [marking2Id],
                        mode: 'and',
                      }
                    ],
                    filterGroups: [],
                  }],
                }
              ],
            },
          ],
        },
      }
    });
    expect(queryResult.data.reports.edges.length).toEqual(2);
    expect(queryResult.data.reports.edges.map((n) => n.node.name).includes('Report2')).toBeTruthy();
    expect(queryResult.data.reports.edges.map((n) => n.node.name).includes('Report4')).toBeTruthy();
  });
  it('should list entities according to filters: complex filters combination with several groups at the same level', async () => {
    // [(confidence > 25) AND (marking = marking2)]
    // OR
    // [(confidence <= 10) AND (report_types = threat-report OR marking = marking1))]
    const queryResult = await queryAsAdmin({
      query: REPORT_LIST_QUERY,
      variables: {
        first: 10,
        filters: {
          mode: 'or',
          filters: [],
          filterGroups: [
            {
              mode: 'and',
              filters: [
                {
                  key: 'confidence',
                  operator: 'gt',
                  values: ['25'],
                  mode: 'or',
                },
                {
                  key: 'objectMarking',
                  operator: 'eq',
                  values: [marking2Id],
                  mode: 'or',
                }
              ],
              filterGroups: [],
            },
            {
              mode: 'and',
              filters: [
                {
                  key: 'confidence',
                  operator: 'lte',
                  values: ['10'],
                  mode: 'or',
                }
              ],
              filterGroups: [{
                mode: 'or',
                filters: [
                  {
                    key: 'report_types',
                    operator: 'eq',
                    values: ['threat-report'],
                    mode: 'or',
                  },
                  {
                    key: 'objectMarking',
                    operator: 'eq',
                    values: [marking1Id],
                    mode: 'or',
                  }
                ],
                filterGroups: [],
              }],
            }
          ],
        },
      }
    });
    expect(queryResult.data.reports.edges.length).toEqual(3);
    expect(queryResult.data.reports.edges.map((n) => n.node.name).includes('Report4')).toBeTruthy();
    expect(queryResult.data.reports.edges.map((n) => n.node.name).includes('Report1')).toBeTruthy();
    expect(queryResult.data.reports.edges.map((n) => n.node.name)).includes('A demo report for testing purposes').toBeTruthy();
  });
  it('should list entities according to filters: filter with \'nil\' and \'not_nil\' operators on arrays', async () => {
    // test for 'nil': objectMarking is empty
    let queryResult = await queryAsAdmin({
      query: REPORT_LIST_QUERY,
      variables: {
        first: 10,
        filters: {
          mode: 'and',
          filters: [
            {
              key: 'objectMarking',
              operator: 'nil',
              values: [],
              mode: 'or',
            }
          ],
          filterGroups: [],
        },
      }
    });
    expect(queryResult.data.reports.edges.length).toEqual(1);
    expect(queryResult.data.reports.edges[0].node.name).toEqual('Report3');
    // test for 'not_nil': objectMarking is not empty
    queryResult = await queryAsAdmin({
      query: REPORT_LIST_QUERY,
      variables: {
        first: 10,
        filters: {
          mode: 'and',
          filters: [
            {
              key: 'objectMarking',
              operator: 'not_nil',
              values: [],
              mode: 'or',
            }
          ],
          filterGroups: [],
        },
      }
    });
    expect(queryResult.data.reports.edges.length).toEqual(4);
    expect(queryResult.data.reports.edges.map((n) => n.node.name).includes('Report3')).toBeFalsy();
  });
  it('should list entities according to filters: \'nil\' / \'not_nil\' operators on strings', async () => {
    // description is empty
    let queryResult = await queryAsAdmin({
      query: REPORT_LIST_QUERY,
      variables: {
        first: 10,
        filters: {
          mode: 'and',
          filters: [
            {
              key: 'description',
              operator: 'nil',
              values: [],
              mode: 'or',
            }
          ],
          filterGroups: [],
        },
      }
    });
    expect(queryResult.data.reports.edges.length).toEqual(2);
    expect(queryResult.data.reports.edges.map((n) => n.node.name).includes('Report3')).toBeTruthy(); // description is empty string
    expect(queryResult.data.reports.edges.map((n) => n.node.name).includes('Report4')).toBeTruthy(); // description is null
    // description is not empty
    queryResult = await queryAsAdmin({
      query: REPORT_LIST_QUERY,
      variables: {
        first: 10,
        filters: {
          mode: 'and',
          filters: [
            {
              key: 'description',
              operator: 'not_nil',
              values: [],
              mode: 'or',
            }
          ],
          filterGroups: [],
        },
      }
    });
    expect(queryResult.data.reports.edges.length).toEqual(3); // 'Report1', 'Report2', 'A demo for testing purpose'
    expect(queryResult.data.reports.edges.map((n) => n.node.name).includes('Report1')).toBeTruthy();
    expect(queryResult.data.reports.edges.map((n) => n.node.name).includes('Report2')).toBeTruthy();
  });
  it('should list entities according to filters: \'nil\' / \'not_nil\' operators on dates', async () => {
    // start_time is empty
    let queryResult = await queryAsAdmin({
      query: RELATIONSHIP_QUERY,
      variables: {
        first: 10,
        filters: {
          mode: 'and',
          filters: [
            {
              key: 'start_time',
              operator: 'nil',
              values: [],
              mode: 'or',
            }
          ],
          filterGroups: [],
        },
      }
    });
    // 4 relationships with no start_time + 4 relationships with start_time <= '1970-01-01T01:00:00.000Z'
    expect(queryResult.data.stixCoreRelationships.edges.length).toEqual(8);
    // stop_time is empty
    queryResult = await queryAsAdmin({
      query: RELATIONSHIP_QUERY,
      variables: {
        first: 10,
        filters: {
          mode: 'and',
          filters: [
            {
              key: 'stop_time',
              operator: 'nil',
              values: [],
              mode: 'or',
            }
          ],
          filterGroups: [],
        },
      }
    });
    // 4 relationships with no stop_time + 3 with stop_time <= '1970-01-01T01:00:00.000Z' + 1 with stop_time = '5138-11-16T09:46:40.000Z'
    expect(queryResult.data.stixCoreRelationships.edges.length).toEqual(8);
    // stop_time is not empty
    queryResult = await queryAsAdmin({
      query: RELATIONSHIP_QUERY,
      variables: {
        first: 10,
        filters: {
          mode: 'and',
          filters: [
            {
              key: 'stop_time',
              operator: 'not_nil',
              values: [],
              mode: 'or',
            },
          ],
          filterGroups: [],
        },
      }
    });
    // 24 relationships - 8 with empty stop_time
    expect(queryResult.data.stixCoreRelationships.edges.length).toEqual(16);
  });
  it('should list entities according to filters: aggregation with filters', async () => {
    // count the number of entities with each marking
    const distributionArgs = {
      field: ID_INTERNAL,
      isTo: true,
      operation: 'count',
      relationship_type: RELATION_OBJECT_MARKING,
      fromTypes: [ENTITY_TYPE_CONTAINER_REPORT],
      toRole: 'object-marking_to',
      toTypes: [ENTITY_TYPE_MARKING_DEFINITION],
    };
    const distribution = await distributionRelations(testContext, ADMIN_USER, distributionArgs);
    // there are 3 markings involved in a relationship with a report: the 2 markings created + the marking of the report in DATA-TEST-STIX2_v2
    expect(distribution.length).toEqual(3);
    const distributionCount = new Map(distribution.map((n) => [n.label, n.value])); // Map<marking internal_id, count>
    expect(distributionCount.get(marking1Id)).toEqual(1); // marking1 is used 1 time (in Report1)
    expect(distributionCount.get(marking2Id)).toEqual(3); // marking2 is used 3 times
  });
  it('should list entities according to filters: filters with multi keys', async () => {
    // (name = Report1) OR (description = Report1)
    const queryResult = await queryAsAdmin({
      query: REPORT_LIST_QUERY,
      variables: {
        first: 10,
        filters: {
          mode: 'and',
          filters: [
            {
              key: ['name', 'lang'], // the keys should have the same type and format
              operator: 'eq',
              values: ['Report1'],
              mode: 'or',
            }
          ],
          filterGroups: [],
        },
      }
    });
    expect(queryResult.data.reports.edges.length).toEqual(2);
    expect(queryResult.data.reports.edges.map((n) => n.node.name).includes('Report1')).toBeTruthy();
    expect(queryResult.data.reports.edges.map((n) => n.node.name).includes('Report2')).toBeTruthy();
  });
  it('should list entities according to filters: combinations of operators and modes with entity_type filter', async () => {
    // objective: test the correct injection of parent types
    // (entity_type is empty)
    let queryResult = await queryAsAdmin({
      query: LIST_QUERY,
      variables: {
        first: 10,
        filters: {
          mode: 'or',
          filters: [
            {
              key: 'entity_type',
              operator: 'nil',
              values: [],
              mode: 'and',
            }
          ],
          filterGroups: [],
        },
      }
    });
    expect(queryResult.data.globalSearch.edges.length).toEqual(0);
    // (entity_type = Malware)
    queryResult = await queryAsAdmin({
      query: LIST_QUERY,
      variables: {
        first: 10,
        filters: {
          mode: 'or',
          filters: [
            {
              key: 'entity_type',
              operator: 'eq',
              values: [ENTITY_TYPE_MALWARE],
              mode: 'and',
            }
          ],
          filterGroups: [],
        },
      }
    });
    expect(queryResult.data.globalSearch.edges.length).toEqual(2);
    queryResult = await queryAsAdmin({
      query: LIST_QUERY,
      variables: {
        first: 10,
        filters: {
          mode: 'or',
          filters: [
            {
              key: 'entity_type',
              operator: 'eq',
              values: [ENTITY_TYPE_MALWARE],
              mode: 'or',
            }
          ],
          filterGroups: [],
        },
      }
    });
    expect(queryResult.data.globalSearch.edges.length).toEqual(2);
    // (entity_type = Report OR container)
    queryResult = await queryAsAdmin({
      query: LIST_QUERY,
      variables: {
        first: 10,
        filters: {
          mode: 'or',
          filters: [
            {
              key: 'entity_type',
              operator: 'eq',
              values: [ENTITY_TYPE_CONTAINER_REPORT, ENTITY_TYPE_CONTAINER],
              mode: 'or',
            }
          ],
          filterGroups: [],
        },
      }
    });
    expect(queryResult.data.globalSearch.edges.length).toEqual(8); // 8 containers: 4 reports in this file + 1 report, 1 note, 1 observed-data, 1 opinion in DATA-TEST-STIXv2_v2
    // (entity_type = Report AND container)
    queryResult = await queryAsAdmin({
      query: LIST_QUERY,
      variables: {
        first: 10,
        filters: {
          mode: 'or',
          filters: [
            {
              key: 'entity_type',
              operator: 'eq',
              values: [ENTITY_TYPE_CONTAINER_REPORT, ENTITY_TYPE_CONTAINER],
              mode: 'and',
            }
          ],
          filterGroups: [],
        },
      }
    });
    expect(queryResult.data.globalSearch.edges.length).toEqual(5); // 5 reports
    // (entity_type = Report AND container AND Stix-Core-Object)
    queryResult = await queryAsAdmin({
      query: LIST_QUERY,
      variables: {
        first: 10,
        filters: {
          mode: 'or',
          filters: [
            {
              key: 'entity_type',
              operator: 'eq',
              values: [ABSTRACT_STIX_CORE_OBJECT, ENTITY_TYPE_CONTAINER_REPORT, ENTITY_TYPE_CONTAINER, ABSTRACT_INTERNAL_OBJECT],
              mode: 'and',
            }
          ],
          filterGroups: [],
        },
      }
    });
    expect(queryResult.data.globalSearch.edges.length).toEqual(5); // 5 reports
    // (entity_type = Malware OR Software)
    queryResult = await queryAsAdmin({
      query: LIST_QUERY,
      variables: {
        first: 10,
        filters: {
          mode: 'or',
          filters: [
            {
              key: 'entity_type',
              operator: 'eq',
              values: [ENTITY_TYPE_MALWARE, 'Software'],
              mode: 'or',
            }
          ],
          filterGroups: [],
        },
      }
    });
    expect(queryResult.data.globalSearch.edges.length).toEqual(3); // 2 malware + 1 software (in DATA-TEST-STIX2_v2.json)
    // (entity_type = Malware) OR (entity_type = Software)
    queryResult = await queryAsAdmin({
      query: LIST_QUERY,
      variables: {
        first: 10,
        filters: {
          mode: 'or',
          filters: [
            {
              key: 'entity_type',
              operator: 'eq',
              values: [ENTITY_TYPE_MALWARE],
              mode: 'or',
            }
          ],
          filterGroups: [
            {
              mode: 'or',
              filters: [
                {
                  key: 'entity_type',
                  operator: 'eq',
                  values: ['Software'],
                  mode: 'or',
                }
              ],
              filterGroups: [],
            }
          ],
        },
      }
    });
    expect(queryResult.data.globalSearch.edges.length).toEqual(3); // 2 malware + 1 software (in DATA-TEST-STIX2_v2.json)
    // (entity_type = Malware AND Software)
    queryResult = await queryAsAdmin({
      query: LIST_QUERY,
      variables: {
        first: 10,
        filters: {
          mode: 'or',
          filters: [
            {
              key: 'entity_type',
              operator: 'eq',
              values: [ENTITY_TYPE_MALWARE, 'Software'],
              mode: 'and',
            }
          ],
          filterGroups: [],
        },
      }
    });
    expect(queryResult.data.globalSearch.edges.length).toEqual(0);
    // (entity_type = Malware) AND (entity_type = Software)
    queryResult = await queryAsAdmin({
      query: LIST_QUERY,
      variables: {
        first: 10,
        filters: {
          mode: 'and',
          filters: [
            {
              key: 'entity_type',
              operator: 'eq',
              values: [ENTITY_TYPE_MALWARE],
              mode: 'and',
            }
          ],
          filterGroups: [
            {
              mode: 'and',
              filters: [
                {
                  key: 'entity_type',
                  operator: 'eq',
                  values: ['Software'],
                  mode: 'and',
                }
              ],
              filterGroups: [],
            }
          ],
        },
      }
    });
    expect(queryResult.data.globalSearch.edges.length).toEqual(0);
    // (entity_type != Malware OR != Software)
    queryResult = await queryAsAdmin({
      query: LIST_QUERY,
      variables: {
        first: 10,
        filters: {
          mode: 'and',
          filters: [
            {
              key: 'entity_type',
              operator: 'not_eq',
              values: [ENTITY_TYPE_MALWARE, 'Software'],
              mode: 'or',
            }
          ],
          filterGroups: [],
        },
      }
    });
    const entitiesNumber = queryResult.data.globalSearch.edges.length; // all the entities
    // (entity_type != Malware AND != Software)
    queryResult = await queryAsAdmin({
      query: LIST_QUERY,
      variables: {
        first: 10,
        filters: {
          mode: 'and',
          filters: [
            {
              key: 'entity_type',
              operator: 'not_eq',
              values: [ENTITY_TYPE_MALWARE, 'Software'],
              mode: 'and',
            }
          ],
          filterGroups: [],
        },
      }
    });
    const entitiesNumberWithoutMalwaresAndSoftware = queryResult.data.globalSearch.edges.length; // all the entities except Malwares and Softwares
    expect(entitiesNumber - entitiesNumberWithoutMalwaresAndSoftware).toEqual(3); // 2 malwares + 1 software
    // (entity_type != Report AND != Container)
    queryResult = await queryAsAdmin({
      query: LIST_QUERY,
      variables: {
        first: 10,
        filters: {
          mode: 'or',
          filters: [
            {
              key: 'entity_type',
              operator: 'not_eq',
              values: [ENTITY_TYPE_CONTAINER_REPORT, ENTITY_TYPE_CONTAINER],
              mode: 'and',
            }
          ],
          filterGroups: [],
        },
      }
    });
    const entitiesExceptContainerNumber = queryResult.data.globalSearch.edges.length; // all the entities that are not containers
    // (entity_type != Report OR != Container)
    queryResult = await queryAsAdmin({
      query: LIST_QUERY,
      variables: {
        first: 10,
        filters: {
          mode: 'or',
          filters: [
            {
              key: 'entity_type',
              operator: 'not_eq',
              values: [ENTITY_TYPE_CONTAINER_REPORT, ENTITY_TYPE_CONTAINER],
              mode: 'or',
            }
          ],
          filterGroups: [],
        },
      }
    });
    const entitiesExceptReportsNumber = queryResult.data.globalSearch.edges.length; // all the entities that are not reports
    expect(entitiesExceptReportsNumber - entitiesExceptContainerNumber).toEqual(3); // number of containers that are not reports: 3 = 1 note, 1 observed-data, 1 opinion
  });
  it('should list entities according to filters: combinations of operators and modes with the special filter key \'id\'', async () => {
    // (id(stix/internal/standard) = standard-XX OR standard-YY)
    let queryResult = await queryAsAdmin({
      query: LIST_QUERY,
      variables: {
        first: 10,
        filters: {
          mode: 'or',
          filters: [
            {
              key: IDS_FILTER,
              operator: 'eq',
              values: ['course-of-action--ae56a49d-5281-45c5-ab95-70a1439c338e', 'attack-pattern--2fc04aa5-48c1-49ec-919a-b88241ef1d17'],
              mode: 'or',
            }
          ],
          filterGroups: [],
        },
      }
    });
    expect(queryResult.data.globalSearch.edges.length).toEqual(2);
    // (id(stix/internal/standard) = internal-XX OR stix-XX)
    queryResult = await queryAsAdmin({
      query: LIST_QUERY,
      variables: {
        first: 10,
        filters: {
          mode: 'or',
          filters: [
            {
              key: IDS_FILTER,
              operator: 'eq',
              values: [report1InternalId, report1StixId],
              mode: 'or',
            }
          ],
          filterGroups: [],
        },
      }
    });
    expect(queryResult.data.globalSearch.edges.length).toEqual(1);
    // (id(stix/internal/standard) = internal-XX AND stix-XX) -> not supported
    queryResult = await queryAsAdmin({
      query: LIST_QUERY,
      variables: {
        first: 10,
        filters: {
          mode: 'or',
          filters: [
            {
              key: IDS_FILTER,
              operator: 'eq',
              values: [report1InternalId, report1StixId],
              mode: 'and',
            }
          ],
          filterGroups: [],
        },
      }
    });
    expect(queryResult.errors[0].message).toEqual('Unsupported filter: \'And\' operator between values of a filter with key = \'ids\' is not supported');
  });
  it('should list entities according to filters: combinations of operators and modes with the special filter key \'source_reliability\'', async () => {
    let queryResult = await queryAsAdmin({
      query: LIST_QUERY,
      variables: {
        first: 20,
        filters: undefined,
      }
    });
    expect(queryResult.data.globalSearch.edges.length).toEqual(44);
    // (source_reliability is empty)
    queryResult = await queryAsAdmin({
      query: LIST_QUERY,
      variables: {
        first: 20,
        filters: {
          mode: 'or',
          filters: [
            {
              key: SOURCE_RELIABILITY_FILTER,
              operator: 'nil',
              values: [],
              mode: 'or',
            }
          ],
          filterGroups: [],
        },
      }
    });
    expect(queryResult.data.globalSearch.edges.length).toEqual(33); // 44 entities - 11 entities with a source reliability = 33
    // (source_reliability is not empty)
    queryResult = await queryAsAdmin({
      query: LIST_QUERY,
      variables: {
        first: 20,
        filters: {
          mode: 'or',
          filters: [
            {
              key: SOURCE_RELIABILITY_FILTER,
              operator: 'not_nil',
              values: [],
              mode: 'or',
            }
          ],
          filterGroups: [],
        },
      }
    });
    expect(queryResult.data.globalSearch.edges.length).toEqual(11); // 11 entities with a source reliability
    // (source_reliability = A - Completely reliable)
    queryResult = await queryAsAdmin({
      query: LIST_QUERY,
      variables: {
        first: 20,
        filters: {
          mode: 'or',
          filters: [
            {
              key: SOURCE_RELIABILITY_FILTER,
              operator: 'eq',
              values: ['A - Completely reliable'],
              mode: 'or',
            }
          ],
          filterGroups: [],
        },
      }
    });
    expect(queryResult.data.globalSearch.edges.length).toEqual(6);
    // (source_reliability != A - Completely reliable)
    queryResult = await queryAsAdmin({
      query: LIST_QUERY,
      variables: {
        first: 20,
        filters: {
          mode: 'or',
          filters: [
            {
              key: SOURCE_RELIABILITY_FILTER,
              operator: 'not_eq',
              values: ['A - Completely reliable'],
              mode: 'or',
            }
          ],
          filterGroups: [],
        },
      }
    });
    expect(queryResult.data.globalSearch.edges.length).toEqual(38); // 44 entities - 6 entities with source reliability equals to A = 38
    // (source_reliability = A - Completely reliable OR B - Usually reliable)
    queryResult = await queryAsAdmin({
      query: LIST_QUERY,
      variables: {
        first: 10,
        filters: {
          mode: 'or',
          filters: [
            {
              key: SOURCE_RELIABILITY_FILTER,
              operator: 'eq',
              values: ['A - Completely reliable', 'B - Usually reliable'],
              mode: 'or',
            }
          ],
          filterGroups: [],
        },
      }
    });
    expect(queryResult.data.globalSearch.edges.length).toEqual(11); // 6 entities with source_reliability A + 5 with source_reliability B
    // (source_reliability = A - Completely reliable AND B - Usually reliable)
    queryResult = await queryAsAdmin({
      query: LIST_QUERY,
      variables: {
        first: 10,
        filters: {
          mode: 'or',
          filters: [
            {
              key: SOURCE_RELIABILITY_FILTER,
              operator: 'eq',
              values: ['A - Completely reliable', 'B - Usually reliable'],
              mode: 'and',
            }
          ],
          filterGroups: [],
        },
      }
    });
    expect(queryResult.data.globalSearch.edges.length).toEqual(0);
    // (source_reliability != A - Completely reliable AND != B - Usually reliable)
    queryResult = await queryAsAdmin({
      query: LIST_QUERY,
      variables: {
        first: 10,
        filters: {
          mode: 'or',
          filters: [
            {
              key: SOURCE_RELIABILITY_FILTER,
              operator: 'not_eq',
              values: ['A - Completely reliable', 'B - Usually reliable'],
              mode: 'and',
            }
          ],
          filterGroups: [],
        },
      }
    });
    const numberOfEntitiesWithSourceReliabilityNotAAndNotB = queryResult.data.globalSearch.edges.length;
    // (source_reliability != A - Completely reliable OR != B - Usually reliable)
    queryResult = await queryAsAdmin({
      query: LIST_QUERY,
      variables: {
        first: 10,
        filters: {
          mode: 'or',
          filters: [
            {
              key: SOURCE_RELIABILITY_FILTER,
              operator: 'not_eq',
              values: ['A - Completely reliable', 'B - Usually reliable'],
              mode: 'or',
            }
          ],
          filterGroups: [],
        },
      }
    });
    const numberOfEntitiesWithSourceReliabilityNotAOrNotB = queryResult.data.globalSearch.edges.length;
    expect(numberOfEntitiesWithSourceReliabilityNotAOrNotB - numberOfEntitiesWithSourceReliabilityNotAAndNotB).toEqual(11); // number of entities with source_reliability A or B
  });
  it('should list entities according to filters: combinations of operators and modes with the special filter key \'computed_reliability\'', async () => {
    // (computed_reliability is empty)
    let queryResult = await queryAsAdmin({
      query: LIST_QUERY,
      variables: {
        first: 20,
        filters: {
          mode: 'or',
          filters: [
            {
              key: COMPUTED_RELIABILITY_FILTER,
              operator: 'nil',
              values: [],
              mode: 'or',
            }
          ],
          filterGroups: [],
        },
      }
    });
    expect(queryResult.data.globalSearch.edges.length).toEqual(31); // 44 - 11 with a source reliability - 2 with a reliability (and no source reliability) = 31
    // (computed_reliability is not empty)
    queryResult = await queryAsAdmin({
      query: LIST_QUERY,
      variables: {
        first: 20,
        filters: {
          mode: 'or',
          filters: [
            {
              key: COMPUTED_RELIABILITY_FILTER,
              operator: 'not_nil',
              values: [],
              mode: 'or',
            }
          ],
          filterGroups: [],
        },
      }
    });
    expect(queryResult.data.globalSearch.edges.length).toEqual(13); // 11 entities with a source reliability + 2 entities with a reliability = 13
    // (computed_reliability = A - Completely reliable)
    queryResult = await queryAsAdmin({
      query: LIST_QUERY,
      variables: {
        first: 20,
        filters: {
          mode: 'or',
          filters: [
            {
              key: COMPUTED_RELIABILITY_FILTER,
              operator: 'eq',
              values: ['A - Completely reliable'],
              mode: 'or',
            }
          ],
          filterGroups: [],
        },
      }
    });
    expect(queryResult.data.globalSearch.edges.length).toEqual(7); // 6 entities with source reliability A + 1 entity with reliability A
    // (computed_reliability = A - Completely reliable OR B - Usually reliable)
    queryResult = await queryAsAdmin({
      query: LIST_QUERY,
      variables: {
        first: 10,
        filters: {
          mode: 'or',
          filters: [
            {
              key: COMPUTED_RELIABILITY_FILTER,
              operator: 'eq',
              values: ['A - Completely reliable', 'B - Usually reliable'],
              mode: 'or',
            }
          ],
          filterGroups: [],
        },
      }
    });
    expect(queryResult.data.globalSearch.edges.length).toEqual(13); // 6 with source_reliability A + 3 with source_reliability B + 1 with reliability A + 1 with reliability B
    // (computed_reliability = A - Completely reliable AND B - Usually reliable)
    queryResult = await queryAsAdmin({
      query: LIST_QUERY,
      variables: {
        first: 10,
        filters: {
          mode: 'or',
          filters: [
            {
              key: COMPUTED_RELIABILITY_FILTER,
              operator: 'eq',
              values: ['A - Completely reliable', 'B - Usually reliable'],
              mode: 'and',
            }
          ],
          filterGroups: [],
        },
      }
    });
    expect(queryResult.data.globalSearch.edges.length).toEqual(0);
  });
  it('should list entities according to filters: filters with a relationship_type key', async () => {
    const location = await storeLoadById(testContext, ADMIN_USER, 'location--c3794ffd-0e71-4670-aa4d-978b4cbdc72c', ENTITY_TYPE_LOCATION);
    const locationInternalId = location.internal_id;
    const intrusionSet = await storeLoadById(testContext, ADMIN_USER, 'intrusion-set--18854f55-ac7c-4634-bd9a-352dd07613b7', ENTITY_TYPE_INTRUSION_SET);
    const intrusionSetInternalId = intrusionSet.internal_id;
    // (objects = internal-id-of-a-location)
    let queryResult = await queryAsAdmin({
      query: LIST_QUERY,
      variables: {
        first: 20,
        filters: {
          mode: 'or',
          filters: [
            {
              key: 'objects',
              operator: 'eq',
              values: [locationInternalId],
              mode: 'or',
            }
          ],
          filterGroups: [],
        },
      }
    });
    expect(queryResult.data.globalSearch.edges.length).toEqual(1); // 1 report contains this location
    // (targets = internal-id-of-a-location)
    queryResult = await queryAsAdmin({
      query: LIST_QUERY,
      variables: {
        first: 20,
        filters: {
          mode: 'or',
          filters: [
            {
              key: 'targets',
              operator: 'eq',
              values: [locationInternalId],
              mode: 'or',
            }
          ],
          filterGroups: [],
        },
      }
    });
    expect(queryResult.data.globalSearch.edges.length).toEqual(1); // 1 intrusion-set targets this location
    expect(queryResult.data.globalSearch.edges[0].node.id).toEqual(intrusionSetInternalId);
  });
  it(`should list relationships according to filters: combinations of operators and modes with the special filter key ${INSTANCE_RELATION_TYPES_FILTER}`, async () => {
    // all stix core relationships
    let queryResult = await queryAsAdmin({
      query: RELATIONSHIP_QUERY,
      variables: {
        first: 20,
        filters: undefined,
      }
    });
    expect(queryResult.data.stixCoreRelationships.edges.length).toEqual(24); // 24 stix core relationships
    // (fromOrToTypes = Malware)
    // <-> fromType = Malware OR toType = Malware
    queryResult = await queryAsAdmin({
      query: RELATIONSHIP_QUERY,
      variables: {
        first: 20,
        filters: {
          mode: 'or',
          filters: [
            {
              key: INSTANCE_RELATION_TYPES_FILTER,
              operator: 'eq',
              values: ['Malware'],
              mode: 'or',
            }
          ],
          filterGroups: [],
        },
      }
    });
    expect(queryResult.data.stixCoreRelationships.edges.length).toEqual(4); // 4 relationship with fromType = Malware or toType = Malware
    queryResult = await queryAsAdmin({
      query: RELATIONSHIP_QUERY,
      variables: {
        first: 20,
        filters: {
          mode: 'or',
          filters: [
            {
              key: RELATION_FROM_TYPES_FILTER,
              operator: 'eq',
              values: ['Malware'],
              mode: 'or',
            },
            {
              key: RELATION_TO_TYPES_FILTER,
              operator: 'eq',
              values: ['Malware'],
              mode: 'or',
            }
          ],
          filterGroups: [],
        },
      }
    });
    expect(queryResult.data.stixCoreRelationships.edges.length).toEqual(4); // 4 relationship with fromType = Malware or toType = Malware
    // (fromOrToTypes != Malware-Analysis)
    queryResult = await queryAsAdmin({
      query: RELATIONSHIP_QUERY,
      variables: {
        first: 20,
        filters: {
          mode: 'or',
          filters: [
            {
              key: INSTANCE_RELATION_TYPES_FILTER,
              operator: 'not_eq',
              values: ['Malware-Analysis'],
              mode: 'or',
            }
          ],
          filterGroups: [],
        },
      }
    });
    // 24 relationships - 1 relationship (relationship--642f6fca-6c5a-495c-9419-9ee0a4a599ee) involving a Malware-Analysis
    expect(queryResult.data.stixCoreRelationships.edges.length).toEqual(23);
    // (fromTypes != Malware-Analysis)
    queryResult = await queryAsAdmin({
      query: RELATIONSHIP_QUERY,
      variables: {
        first: 20,
        filters: {
          mode: 'or',
          filters: [
            {
              key: RELATION_FROM_TYPES_FILTER,
              operator: 'not_eq',
              values: ['Malware-Analysis'],
              mode: 'or',
            }
          ],
          filterGroups: [],
        },
      }
    });
    // 24 relationships - 1 relationship (relationship--642f6fca-6c5a-495c-9419-9ee0a4a599ee) with a Malware-Analysis as source ref
    expect(queryResult.data.stixCoreRelationships.edges.length).toEqual(23);
    // (fromTypes = Malware)
    queryResult = await queryAsAdmin({
      query: RELATIONSHIP_QUERY,
      variables: {
        first: 20,
        filters: {
          mode: 'or',
          filters: [
            {
              key: RELATION_FROM_TYPES_FILTER,
              operator: 'eq',
              values: ['Malware'],
              mode: 'or',
            }
          ],
          filterGroups: [],
        },
      }
    });
    expect(queryResult.data.stixCoreRelationships.edges.length).toEqual(2); // 2 relationships with a Malware as source ref
    // (fromTypes = Malware OR Malware-Analysis)
    queryResult = await queryAsAdmin({
      query: RELATIONSHIP_QUERY,
      variables: {
        first: 20,
        filters: {
          mode: 'or',
          filters: [
            {
              key: RELATION_FROM_TYPES_FILTER,
              operator: 'eq',
              values: ['Malware', 'Malware-Analysis'],
              mode: 'or',
            }
          ],
          filterGroups: [],
        },
      }
    });
    expect(queryResult.data.stixCoreRelationships.edges.length).toEqual(3); // 2 relationships with a Malware as source ref + 1 with Malware-Analysis
    // (fromTypes = Malware AND Malware-Analysis)
    queryResult = await queryAsAdmin({
      query: RELATIONSHIP_QUERY,
      variables: {
        first: 20,
        filters: {
          mode: 'or',
          filters: [
            {
              key: RELATION_FROM_TYPES_FILTER,
              operator: 'eq',
              values: ['Malware', 'Malware-Analysis'],
              mode: 'and',
            }
          ],
          filterGroups: [],
        },
      }
    });
    expect(queryResult.data.stixCoreRelationships.edges.length).toEqual(0); // 0 relationships with a Malware and a Malware-Analysis as source ref
    // (toTypes != Malware-Analysis)
    queryResult = await queryAsAdmin({
      query: RELATIONSHIP_QUERY,
      variables: {
        first: 20,
        filters: {
          mode: 'or',
          filters: [
            {
              key: RELATION_TO_TYPES_FILTER,
              operator: 'not_eq',
              values: ['Malware-Analysis'],
              mode: 'or',
            }
          ],
          filterGroups: [],
        },
      }
    });
    expect(queryResult.data.stixCoreRelationships.edges.length).toEqual(24); // all the relationships have no malware analysis as target ref
    // (fromOrToTypes = Attack-Pattern OR Malware)
    queryResult = await queryAsAdmin({
      query: RELATIONSHIP_QUERY,
      variables: {
        first: 20,
        filters: {
          mode: 'or',
          filters: [
            {
              key: INSTANCE_RELATION_TYPES_FILTER,
              operator: 'eq',
              values: ['Attack-Pattern', 'Malware'],
              mode: 'or',
            }
          ],
          filterGroups: [],
        },
      }
    });
    expect(queryResult.data.stixCoreRelationships.edges.length).toEqual(5);
    // (fromOrToTypes = Attack-Pattern AND Malware)
    queryResult = await queryAsAdmin({
      query: RELATIONSHIP_QUERY,
      variables: {
        first: 20,
        filters: {
          mode: 'or',
          filters: [
            {
              key: INSTANCE_RELATION_TYPES_FILTER,
              operator: 'eq',
              values: ['Attack-Pattern', 'Malware'],
              mode: 'and',
            }
          ],
          filterGroups: [],
        },
      }
    });
    expect(queryResult.data.stixCoreRelationships.edges.length).toEqual(2);
    // (fromOrToTypes != Attack-Pattern AND Malware)
    queryResult = await queryAsAdmin({
      query: RELATIONSHIP_QUERY,
      variables: {
        first: 20,
        filters: {
          mode: 'or',
          filters: [
            {
              key: INSTANCE_RELATION_TYPES_FILTER,
              operator: 'not_eq',
              values: ['Attack-Pattern', 'Malware'],
              mode: 'and',
            }
          ],
          filterGroups: [],
        },
      }
    });
    expect(queryResult.data.stixCoreRelationships.edges.length).toEqual(19); // (24 relationships) - (5 relationships involving malware or attack pattern) = 19
    // (fromOrToTypes is empty)
    queryResult = await queryAsAdmin({
      query: RELATIONSHIP_QUERY,
      variables: {
        first: 20,
        filters: {
          mode: 'or',
          filters: [
            {
              key: INSTANCE_RELATION_TYPES_FILTER,
              operator: 'nil',
              values: [],
              mode: 'and',
            }
          ],
          filterGroups: [],
        },
      }
    });
    expect(queryResult.data.stixCoreRelationships.edges.length).toEqual(0);
    // (fromOrToId is empty)
    queryResult = await queryAsAdmin({
      query: RELATIONSHIP_QUERY,
      variables: {
        first: 20,
        filters: {
          mode: 'or',
          filters: [
            {
              key: INSTANCE_RELATION_FILTER,
              operator: 'nil',
              values: [],
              mode: 'and',
            }
          ],
          filterGroups: [],
        },
      }
    });
    expect(queryResult.data.stixCoreRelationships.edges.length).toEqual(0);
    // (fromOrToTypes is not empty)
    queryResult = await queryAsAdmin({
      query: RELATIONSHIP_QUERY,
      variables: {
        first: 20,
        filters: {
          mode: 'or',
          filters: [
            {
              key: INSTANCE_RELATION_TYPES_FILTER,
              operator: 'not_nil',
              values: [],
              mode: 'and',
            }
          ],
          filterGroups: [],
        },
      }
    });
    expect(queryResult.data.stixCoreRelationships.edges.length).toEqual(24);
    // (fromOrToId is not empty)
    queryResult = await queryAsAdmin({
      query: RELATIONSHIP_QUERY,
      variables: {
        first: 20,
        filters: {
          mode: 'or',
          filters: [
            {
              key: INSTANCE_RELATION_FILTER,
              operator: 'not_nil',
              values: [],
              mode: 'and',
            }
          ],
          filterGroups: [],
        },
      }
    });
    expect(queryResult.data.stixCoreRelationships.edges.length).toEqual(24);
  });
  it('should list entities according to filters: filters with not supported keys', async () => {
    // bad_filter_key = XX
    const queryResult = await queryAsAdmin({ query: LIST_QUERY,
      variables: {
        first: 20,
        filters: {
          mode: 'or',
          filters: [
            {
              key: 'bad_filter_key',
              operator: 'eq',
              values: ['Report'],
              mode: 'or',
            }
          ],
          filterGroups: [],
        },
      } });
    expect(queryResult.errors.length).toEqual(1);
  });
  it('should list entities according to search filters with trunc word', async () => {
    const queryResult = await queryAsAdmin({ query: REPORT_LIST_QUERY,
      variables: {
        first: 25,
        filters: {
          mode: 'and',
          filters: [{
            key: 'description',
            // Look for this description value 'Report for testing purposes (random data).'
            values: ['rt for testing purposes (rando'],
            operator: 'search',
            mode: 'or',
          }],
          filterGroups: [],
        },
      } });
    expect(queryResult.data.reports.edges.length).toEqual(1);
  });

  it('should list entities according to search filters with trunc word and unordered', async () => {
    const queryResult = await queryAsAdmin({ query: REPORT_LIST_QUERY,
      variables: {
        first: 25,
        filters: {
          mode: 'and',
          filters: [{
            key: 'description',
            // Look for this description value 'Report for testing purposes (random data).'
            values: ['for rt testing (rando purposes '],
            operator: 'search',
            mode: 'or',
          }],
          filterGroups: [],
        },
      } });
    expect(queryResult.data.reports.edges.length).toEqual(1);
  });

  it('should not find entities according to search filters with trunc word and double quote', async () => {
    const queryResult = await queryAsAdmin({ query: REPORT_LIST_QUERY,
      variables: {
        first: 25,
        filters: {
          mode: 'and',
          filters: [{
            key: 'description',
            // Look for this description value'Report for testing purposes (random data).'
            values: ['"rt for testing purposes (rando"'],
            operator: 'search',
            mode: 'or',
          }],
          filterGroups: [],
        },
      } });
    expect(queryResult.data.reports.edges.length).toEqual(0);
  });
  it('should find entities according to search filters with double quote', async () => {
    const queryResult = await queryAsAdmin({ query: REPORT_LIST_QUERY,
      variables: {
        first: 25,
        filters: {
          mode: 'and',
          filters: [{
            key: 'description',
            // Look for this description value'Report for testing purposes (random data).'
            values: ['"for testing purposes"'],
            operator: 'search',
            mode: 'or',
          }],
          filterGroups: [],
        },
      } });
    expect(queryResult.data.reports.edges.length).toEqual(1);
  });

  it('should not find any entities according to search filters which is not in any description', async () => {
    const queryResult = await queryAsAdmin({ query: REPORT_LIST_QUERY,
      variables: {
        first: 25,
        filters: {
          mode: 'and',
          filters: [{
            key: 'description',
            values: ['Abracadabra'],
            operator: 'search',
            mode: 'or',
          }],
          filterGroups: [],
        },
      } });
    expect(queryResult.data.reports.edges.length).toEqual(0);
  });

  it('should find entities according to search filters with one existing word and another word which is not present in any description', async () => {
    const queryResult = await queryAsAdmin({ query: REPORT_LIST_QUERY,
      variables: {
        first: 25,
        filters: {
          mode: 'and',
          filters: [{
            key: 'description',
            values: ['Abracadabra report'],
            operator: 'search',
            mode: 'or',
          }],
          filterGroups: [],
        },
      } });
    expect(queryResult.data.reports.edges.length).toEqual(3);
  });

  it('should find entities according to search filters on short string', async () => {
    const queryResult = await queryAsAdmin({ query: REPORT_LIST_QUERY,
      variables: {
        first: 25,
        filters: {
          mode: 'and',
          filters: [{
            key: 'name',
            // Look for this name value 'A demo report for testing purposes'
            values: ['port for testi'],
            operator: 'search',
            mode: 'or',
          }],
          filterGroups: [],
        },
      } });
    expect(queryResult.data.reports.edges.length).toEqual(1);
  });

  it('should find entities according to search filters on unordered short string', async () => {
    const queryResult = await queryAsAdmin({ query: REPORT_LIST_QUERY,
      variables: {
        first: 25,
        filters: {
          mode: 'and',
          filters: [{
            key: 'name',
            // Look for this name value 'A demo report for testing purposes'
            values: ['testi port for'],
            operator: 'search',
            mode: 'or',
          }],
          filterGroups: [],
        },
      } });
    expect(queryResult.data.reports.edges.length).toEqual(1);
  });

  it('should not find entities according to search filters on trunc short string and double quotes', async () => {
    const queryResult = await queryAsAdmin({ query: REPORT_LIST_QUERY,
      variables: {
        first: 25,
        filters: {
          mode: 'and',
          filters: [{
            key: 'name',
            // Look for this name value 'A demo report for testing purposes'
            values: ['"eport for tes"'],
            operator: 'search',
            mode: 'or',
          }],
          filterGroups: [],
        },
      } });
    expect(queryResult.data.reports.edges.length).toEqual(0);
  });

  it('should find entities according to search filters on short string with double quotes', async () => {
    const queryResult = await queryAsAdmin({ query: REPORT_LIST_QUERY,
      variables: {
        first: 25,
        filters: {
          mode: 'and',
          filters: [{
            key: 'name',
            // Look for this name value 'A demo report for testing purposes'
            values: ['"report for testing"'],
            operator: 'search',
            mode: 'or',
          }],
          filterGroups: [],
        },
      } });
    expect(queryResult.data.reports.edges.length).toEqual(1);
  });

  it('should not find any entities according to search filters on abracadra', async () => {
    const queryResult = await queryAsAdmin({ query: REPORT_LIST_QUERY,
      variables: {
        first: 25,
        filters: {
          mode: 'and',
          filters: [{
            key: 'name',
            values: ['abracadra'],
            operator: 'search',
            mode: 'or',
          }],
          filterGroups: [],
        },
      } });
    expect(queryResult.data.reports.edges.length).toEqual(0);
  });

  it('should find one entity according to search filters on abracadra and testing', async () => {
    const queryResult = await queryAsAdmin({ query: REPORT_LIST_QUERY,
      variables: {
        first: 25,
        filters: {
          mode: 'and',
          filters: [{
            key: 'name',
            values: ['abracadra testing'],
            operator: 'search',
            mode: 'or',
          }],
          filterGroups: [],
        },
      } });
    expect(queryResult.data.reports.edges.length).toEqual(1);
  });

  it('should test environment deleted', async () => {
    const DELETE_REPORT_QUERY = gql`
        mutation reportDelete($id: ID!) {
            reportEdit(id: $id) {
                delete
            }
        }
    `;
    const DELETE_MARKING_QUERY = gql`
        mutation markingDefinitionDelete($id: ID!) {
            markingDefinitionEdit(id: $id) {
                delete
            }
        }
    `;
    // Delete the reports
    await queryAsAdmin({
      query: DELETE_REPORT_QUERY,
      variables: { id: report1InternalId },
    });
    await queryAsAdmin({
      query: DELETE_REPORT_QUERY,
      variables: { id: report2InternalId },
    });
    await queryAsAdmin({
      query: DELETE_REPORT_QUERY,
      variables: { id: report3InternalId },
    });
    await queryAsAdmin({
      query: DELETE_REPORT_QUERY,
      variables: { id: report4InternalId },
    });
    await queryAsAdmin({
      query: DELETE_MARKING_QUERY,
      variables: { id: marking1Id },
    });
    await queryAsAdmin({
      query: DELETE_MARKING_QUERY,
      variables: { id: marking2Id },
    });
    // Verify is no longer found
    let queryResult;
    queryResult = await queryAsAdmin({ query: READ_REPORT_QUERY, variables: { id: report1StixId } });
    expect(queryResult).not.toBeNull();
    expect(queryResult.data.report).toBeNull();
    queryResult = await queryAsAdmin({ query: READ_REPORT_QUERY, variables: { id: report2StixId } });
    expect(queryResult).not.toBeNull();
    expect(queryResult.data.report).toBeNull();
    queryResult = await queryAsAdmin({ query: READ_REPORT_QUERY, variables: { id: report3StixId } });
    expect(queryResult).not.toBeNull();
    expect(queryResult.data.report).toBeNull();
    queryResult = await queryAsAdmin({ query: READ_REPORT_QUERY, variables: { id: report4StixId } });
    expect(queryResult).not.toBeNull();
    expect(queryResult.data.report).toBeNull();
    queryResult = await queryAsAdmin({ query: READ_MARKING_QUERY, variables: { id: marking1StixId } });
    expect(queryResult).not.toBeNull();
    expect(queryResult.data.markingDefinition).toBeNull();
    queryResult = await queryAsAdmin({ query: READ_MARKING_QUERY, variables: { id: marking2StixId } });
    expect(queryResult).not.toBeNull();
    expect(queryResult.data.markingDefinition).toBeNull();
  });
});
