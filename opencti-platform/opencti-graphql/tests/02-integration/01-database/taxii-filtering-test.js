import { describe, expect, it } from 'vitest';
import gql from 'graphql-tag';
import { ADMIN_USER, queryAsAdmin, testContext } from '../../utils/testQuery';
import { addAllowedMarkingDefinition } from '../../../src/domain/markingDefinition';
import { collectionQuery, taxiiCollectionEditField } from '../../../src/domain/taxii';
import { storeLoadById } from '../../../src/database/middleware-loader';
import { ENTITY_TYPE_TAXII_COLLECTION } from '../../../src/schema/internalObject';

// test taxii collections filtering (same behaviors for feeds filtering)

const READ_TAXII_QUERY = gql`
    query taxiiCollection($id: String!) {
        taxiiCollection(id: $id) {
            id
            name
        }
    }
`;

const READ_REPORT_QUERY = gql`
    query report($id: String!) {
        report(id: $id) {
            id
            name
        }
    }
`;

const READ_CITY_QUERY = gql`
    query city($id: String!) {
        city(id: $id) {
            id
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

describe('Complex filters combinations, behavior tested on taxii collections', () => {
  let taxiiInternalId;
  const taxiiStixId = 'taxii--994491f0-f114-4e41-bcf0-3288c0324f01';
  let marking1StixId;
  let marking1Id;
  const reportStixId = 'report--994491f0-f114-4e41-bcf0-3288c0324f59';
  let reportInternalId;
  const city1StixId = 'city--994491f0-f114-4e41-bcf0-3288c0324f01';
  let city1InternalId;
  const city2StixId = 'city--994491f0-f114-4e41-bcf0-3288c0324f02';
  let city2InternalId;
  const city3StixId = 'city--994491f0-f114-4e41-bcf0-3288c0324f03';
  let city3InternalId;
  let changeTaxiiFilters;
  it('should testing environnement created', async () => {
    // Create a marking
    const marking1Input = {
      definition_type: 'TEST',
      definition: 'TEST:1',
      x_opencti_color: '#ffffff',
      x_opencti_order: 1,
    };
    const marking1 = await addAllowedMarkingDefinition(testContext, ADMIN_USER, marking1Input);
    marking1StixId = marking1.standard_id;
    marking1Id = marking1.id;
    // Create the taxii collection
    const CREATE_TAXII_QUERY = gql`
        mutation TaxiiCollectionAdd($input: TaxiiCollectionAddInput!) {
            taxiiCollectionAdd(input: $input) {
                id
                name
            }
        }
    `;
    const TAXII = {
      input: {
        name: 'Taxii',
        description: 'Taxii description',
        filters: undefined,
      },
    };
    const taxii = await queryAsAdmin({
      query: CREATE_TAXII_QUERY,
      variables: TAXII,
    });
    expect(taxii).not.toBeNull();
    expect(taxii.data.taxiiCollectionAdd).not.toBeNull();
    expect(taxii.data.taxiiCollectionAdd.name).toEqual('Taxii');
    taxiiInternalId = taxii.data.taxiiCollectionAdd.id;
    // Create a report
    const CREATE_REPORT_QUERY = gql`
        mutation ReportAdd($input: ReportAddInput!) {
            reportAdd(input: $input) {
                id
                standard_id
                name
            }
        }
    `;
    // Create the report
    const REPORT_TO_CREATE = {
      input: {
        stix_id: reportStixId,
        name: 'Report',
        description: 'Report description',
        published: '2023-02-20T00:51:35.000Z',
        objectMarking: [marking1StixId],
        confidence: 90,
      },
    };
    const report = await queryAsAdmin({
      query: CREATE_REPORT_QUERY,
      variables: REPORT_TO_CREATE,
    });
    expect(report).not.toBeNull();
    expect(report.data.reportAdd).not.toBeNull();
    expect(report.data.reportAdd.name).toEqual('Report');
    reportInternalId = report.data.reportAdd.id;
    // Create the cities
    const CREATE_CITY_QUERY = gql`
        mutation CityAdd($input: CityAddInput!) {
            cityAdd(input: $input) {
                id
                standard_id
                name
            }
        }
    `;
    // Create the cities
    const CITY1_TO_CREATE = {
      input: {
        stix_id: city1StixId,
        name: 'City1',
        description: 'City1 description',
        objectMarking: ['XXX'],
        confidence: 10,
      },
    };
    const city1 = await queryAsAdmin({
      query: CREATE_CITY_QUERY,
      variables: CITY1_TO_CREATE,
    });
    expect(city1).not.toBeNull();
    expect(city1.data.cityAdd).not.toBeNull();
    expect(city1.data.cityAdd.name).toEqual('City1');
    city1InternalId = city1.data.cityAdd.id;
    const CITY2_TO_CREATE = {
      input: {
        stix_id: city2StixId,
        name: 'City2',
        description: 'City2 description',
        objectMarking: [],
        confidence: 20,
      },
    };
    const city2 = await queryAsAdmin({
      query: CREATE_CITY_QUERY,
      variables: CITY2_TO_CREATE,
    });
    expect(city2).not.toBeNull();
    expect(city2.data.cityAdd).not.toBeNull();
    expect(city2.data.cityAdd.name).toEqual('City2');
    city2InternalId = city2.data.cityAdd.id;
    const CITY3_TO_CREATE = {
      input: {
        stix_id: city3StixId,
        name: 'City3',
        description: 'City3 description',
        confidence: 30,
      },
    };
    const city3 = await queryAsAdmin({
      query: CREATE_CITY_QUERY,
      variables: CITY3_TO_CREATE,
    });
    expect(city3).not.toBeNull();
    expect(city3.data.cityAdd).not.toBeNull();
    expect(city3.data.cityAdd.name).toEqual('City3');
    city3InternalId = city3.data.cityAdd.id;
    // utils
    changeTaxiiFilters = async (newFilters) => {
      const editInput = [{
        key: 'filters',
        operation: 'replace',
        value: [JSON.stringify(newFilters)] }];
      await taxiiCollectionEditField(testContext, ADMIN_USER, taxiiInternalId, editInput);
    };
  });
  it('should list entities according to the taxii collection filters', async () => {
    let taxiiCollection;
    let edgeIds;
    // --- 01. Simple filter --- //
    // entity_type = Report
    await changeTaxiiFilters({
      mode: 'and',
      filters: [{
        key: 'entity_type',
        values: ['Report'],
      }],
      filterGroups: [],
    });
    taxiiCollection = await storeLoadById(testContext, ADMIN_USER, taxiiInternalId, ENTITY_TYPE_TAXII_COLLECTION);
    const { edges: results1 } = await collectionQuery(testContext, ADMIN_USER, taxiiCollection, {});
    edgeIds = results1.map((e) => e.node.internal_id);
    const edgeNames = results1.map((e) => e.node.name);
    expect(edgeIds.length).toEqual(2); // the report created + the report in DATA-TEST-STIX2_v2
    expect(edgeIds).includes(reportInternalId).toBeTruthy();
    expect(edgeNames).includes('Report').toBeTruthy();
    expect(edgeNames).includes('A demo report for testing purposes').toBeTruthy();
    // --- 02. Simple filter with no result --- //
    // entity_type = Position
    await changeTaxiiFilters({
      mode: 'and',
      filters: [{
        key: 'entity_type',
        values: ['Position'],
      }],
      filterGroups: [],
    });
    taxiiCollection = await storeLoadById(testContext, ADMIN_USER, taxiiInternalId, ENTITY_TYPE_TAXII_COLLECTION);
    const { edges: results2 } = await collectionQuery(testContext, ADMIN_USER, taxiiCollection, {});
    edgeIds = results2.map((e) => e.node.internal_id);
    expect(edgeIds.length).toEqual(0);
    // --- 03. Different global modes --- //
    // global mode = 'or'
    await changeTaxiiFilters({
      mode: 'or',
      filters: [
        {
          key: 'entity_type',
          values: ['Report'],
        },
        {
          key: 'name',
          values: ['City2'],
        }
      ],
      filterGroups: [],
    });
    taxiiCollection = await storeLoadById(testContext, ADMIN_USER, taxiiInternalId, ENTITY_TYPE_TAXII_COLLECTION);
    const { edges: results3_1 } = await collectionQuery(testContext, ADMIN_USER, taxiiCollection, {});
    edgeIds = results3_1.map((e) => e.node.internal_id);
    expect(edgeIds.length).toEqual(3); // the report + city2 + the report in DATA-TEST-STIX2_v2
    // global mode = 'and'
    await changeTaxiiFilters({
      mode: 'and',
      filters: [
        {
          key: 'entity_type',
          values: ['Report'],
        },
        {
          key: 'name',
          values: ['City2'],
        }
      ],
      filterGroups: [],
    });
    taxiiCollection = await storeLoadById(testContext, ADMIN_USER, taxiiInternalId, ENTITY_TYPE_TAXII_COLLECTION);
    const { edges: results3_2 } = await collectionQuery(testContext, ADMIN_USER, taxiiCollection, {});
    edgeIds = results3_2.map((e) => e.node.internal_id);
    expect(edgeIds.length).toEqual(0);
    // --- 04. filters and filter groups with different operators --- //
    // (confidence >= 90) OR (confidence = 20 AND entity_type != City AND entity_type != Position)
    await changeTaxiiFilters({
      mode: 'or',
      filters: [{
        key: 'confidence',
        values: ['90'],
        operator: 'eq',
      }],
      filterGroups: [{
        mode: 'and',
        filters: [
          {
            key: 'confidence',
            values: ['20'],
            operator: 'eq',
          },
          {
            key: 'entity_type',
            values: ['City', 'Position'],
            operator: 'not_eq',
            mode: 'and',
          },
        ],
        filterGroups: [],
      }],
    });
    taxiiCollection = await storeLoadById(testContext, ADMIN_USER, taxiiInternalId, ENTITY_TYPE_TAXII_COLLECTION);
    const { edges: results4 } = await collectionQuery(testContext, ADMIN_USER, taxiiCollection, {});
    edgeIds = results4.map((e) => e.node.internal_id);
    expect(edgeIds.length).toEqual(3); // report1 + the 2 relationship with confidence = 20 in DATA-TEXT-STIX2_v2
    expect(edgeIds).includes(reportInternalId).toBeTruthy();
    // --- 05. filters and filter groups in 3 imbrication levels --- //
    // (entity_type = CITY OR REPORT)
    // AND
    // (name = City2 OR
    //      (confidence > 25 AND entity_type = Report))
    await changeTaxiiFilters({
      mode: 'and',
      filters: [{
        key: 'entity_type',
        values: ['City', 'Report'],
        mode: 'or',
      }],
      filterGroups: [{
        mode: 'or',
        filters: [
          {
            key: 'name',
            values: ['City2'],
          },
        ],
        filterGroups: [{
          mode: 'and',
          filters: [
            {
              key: 'entity_type',
              values: ['Report'],
              operator: 'eq',
            },
            {
              key: 'confidence',
              values: ['25'],
              operator: 'gt',
            }
          ],
          filterGroups: [],
        }],
      }],
    });
    taxiiCollection = await storeLoadById(testContext, ADMIN_USER, taxiiInternalId, ENTITY_TYPE_TAXII_COLLECTION);
    const { edges: results5 } = await collectionQuery(testContext, ADMIN_USER, taxiiCollection, {});
    edgeIds = results5.map((e) => e.node.internal_id);
    expect(edgeIds.length).toEqual(2);
    expect(edgeIds).includes(reportInternalId).toBeTruthy();
    expect(edgeIds).includes(city2InternalId).toBeTruthy();
    // --- 06. filters with nil operator --- //
    // (published is empty) AND (confidence > 25)
    await changeTaxiiFilters({
      mode: 'and',
      filters: [
        {
          key: 'published',
          values: [],
          operator: 'nil',
        },
        {
          key: 'confidence',
          values: ['25'],
          operator: 'gt',
        },
        {
          key: 'entity_type',
          values: ['City', 'Report'],
          operator: 'eq',
          mode: 'or',
        }
      ],
      filterGroups: [],
    });
    taxiiCollection = await storeLoadById(testContext, ADMIN_USER, taxiiInternalId, ENTITY_TYPE_TAXII_COLLECTION);
    const { edges: results6 } = await collectionQuery(testContext, ADMIN_USER, taxiiCollection, {});
    edgeIds = results6.map((e) => e.node.internal_id);
    expect(edgeIds.length).toEqual(2); // City3 + Heitzing in DATA_STIX2_v2 (no confidence so inserted with user's confidence which is 100)
    expect(edgeIds[1]).toEqual(city3InternalId);
    // --- 07. filters with keys that require a conversion --- //
    // objectMarking = marking1
    await changeTaxiiFilters({
      mode: 'and',
      filters: [{
        key: 'objectMarking',
        values: [marking1Id],
      }],
      filterGroups: [],
    });
    taxiiCollection = await storeLoadById(testContext, ADMIN_USER, taxiiInternalId, ENTITY_TYPE_TAXII_COLLECTION);
    const { edges: results7 } = await collectionQuery(testContext, ADMIN_USER, taxiiCollection, {});
    edgeIds = results7.map((e) => e.node.internal_id);
    expect(edgeIds.length).toEqual(1);
    expect(edgeIds[0]).toEqual(reportInternalId);
  });
  it('should test environnement deleted', async () => {
    const DELETE_TAXII_QUERY = gql`
        mutation taxiiCollectionDelete($id: ID!) {
            taxiiCollectionEdit(id: $id) {
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
    const DELETE_REPORT_QUERY = gql`
        mutation reportDelete($id: ID!) {
            reportEdit(id: $id) {
                delete
            }
        }
    `;
    const DELETE_CITY_QUERY = gql`
        mutation cityDelete($id: ID!) {
            cityEdit(id: $id) {
                delete
            }
        }
    `;
    // Delete the reports
    await queryAsAdmin({
      query: DELETE_TAXII_QUERY,
      variables: { id: taxiiInternalId },
    });
    await queryAsAdmin({
      query: DELETE_MARKING_QUERY,
      variables: { id: marking1Id },
    });
    await queryAsAdmin({
      query: DELETE_REPORT_QUERY,
      variables: { id: reportInternalId },
    });
    await queryAsAdmin({
      query: DELETE_CITY_QUERY,
      variables: { id: city1InternalId },
    });
    await queryAsAdmin({
      query: DELETE_CITY_QUERY,
      variables: { id: city2InternalId },
    });
    await queryAsAdmin({
      query: DELETE_CITY_QUERY,
      variables: { id: city3InternalId },
    });
    // Verify is no longer found
    let queryResult;
    queryResult = await queryAsAdmin({ query: READ_MARKING_QUERY, variables: { id: marking1StixId } });
    expect(queryResult).not.toBeNull();
    expect(queryResult.data.markingDefinition).toBeNull();
    queryResult = await queryAsAdmin({ query: READ_TAXII_QUERY, variables: { id: taxiiStixId } });
    expect(queryResult).not.toBeNull();
    expect(queryResult.data.taxiiCollection).toBeNull();
    queryResult = await queryAsAdmin({ query: READ_REPORT_QUERY, variables: { id: reportStixId } });
    expect(queryResult).not.toBeNull();
    expect(queryResult.data.report).toBeNull();
    queryResult = await queryAsAdmin({ query: READ_CITY_QUERY, variables: { id: city1StixId } });
    expect(queryResult).not.toBeNull();
    expect(queryResult.data.city).toBeNull();
    queryResult = await queryAsAdmin({ query: READ_CITY_QUERY, variables: { id: city2StixId } });
    expect(queryResult).not.toBeNull();
    expect(queryResult.data.city).toBeNull();
    queryResult = await queryAsAdmin({ query: READ_CITY_QUERY, variables: { id: city3StixId } });
    expect(queryResult).not.toBeNull();
    expect(queryResult.data.city).toBeNull();
  });
});
