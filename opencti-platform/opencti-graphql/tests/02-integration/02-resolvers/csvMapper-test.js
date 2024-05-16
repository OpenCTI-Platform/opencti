import { expect, it, describe, beforeAll, afterAll } from 'vitest';
import gql from 'graphql-tag';
import { internalAdminQuery, queryAsAdmin } from '../../utils/testQuery';
import { ABSTRACT_STIX_CORE_RELATIONSHIP } from '../../../src/schema/general';

const MAPPER_INPUT = {
  name: 'super mapper',
  has_header: true,
  separator: ',',
  representations: JSON.stringify([
    {
      id: 'representation-area',
      type: 'entity',
      target: {
        entity_type: 'Administrative-Area'
      },
      attributes: [
        {
          key: 'name',
          column: {
            column_name: 'A',
          }
        },
        {
          key: 'description',
          column: {
            column_name: 'B',
          }
        }
      ]
    },
    {
      id: 'representation-malware',
      type: 'entity',
      target: {
        entity_type: 'Malware'
      },
      attributes: [
        {
          key: 'name',
          column: {
            column_name: 'E',
          }
        },
        {
          key: 'is_family',
          column: {
            column_name: 'F',
          }
        },
        {
          key: 'malware_types',
          column: {
            column_name: 'G',
          }
        }
      ]
    },
    {
      id: 'rel-area-malware',
      type: 'relationship',
      target: {
        entity_type: 'targets'
      },
      attributes: [
        {
          key: 'from',
          based_on: {
            representations: [
              'representation-malware'
            ]
          }
        },
        {
          key: 'to',
          based_on: {
            representations: [
              'representation-area'
            ]
          }
        }
      ]
    }
  ]),
  skipLineChar: '#',
};
const CREATE_QUERY = gql`
  mutation CsvMapperAdd($input: CsvMapperAddInput!) {
    csvMapperAdd(input: $input) {
      id
      standard_id
      name
      has_header
      separator
      skipLineChar
      representations {
        id
        type
        from
        to
        target {
          entity_type
          column_based {
            column_reference
            operator
            value
          }
        }
        attributes {
          key
          ref {
            id
            multiple
            ids
          }
          based_on {
            representations
          }
          column {
            configuration {
              pattern_date
              separator
              timezone
            }
            column_name
          }
          default_values {
            name
            id
          }
        }
      }
    }
  }
`;

const READ_QUERY = gql`
  query CsvMapper($id: String!) {
    csvMapper(id: $id) {
      id
      name
      has_header
      separator
      skipLineChar
      representations {
        id
      }
    }
  }
`;

const LIST_QUERY = gql`
  query CsvMappers(
    $first: Int
    $after: ID
    $orderBy: CsvMapperOrdering
    $orderMode: OrderingMode
    $filters: FilterGroup
    $search: String
  ) {
    csvMappers(
      first: $first
      after: $after
      orderBy: $orderBy
      orderMode: $orderMode
      filters: $filters
      search: $search
    ) {
      edges {
        node {
          id
          name
          has_header
          separator
          skipLineChar
          representations {
            id
          }
        }
      }
    }
  }
`;

const MAPPER_TEST_CONTENT = `area name,area desc,area lat,area lng,mal name,mal family,mal types
morbihan,,2,-2,vador,TRUE,ddos`;
const TEST_QUERY = gql`
  query CsvMapperTest($configuration: String!, $content: String!) {
    csvMapperTest(configuration: $configuration, content: $content) {
      nbEntities
      nbRelationships
      objects
    }
  }
`;

const DELETE_MUTATION = gql`
  mutation CsvMapperDelete($id: ID!) {
    csvMapperDelete(id: $id)
  }
`;

const LIST_SCHEMAS_QUERY = gql`
  query CsvMapperSchemaAttributes {
    csvMapperSchemaAttributes {
      name
      attributes {
        name
        mandatory
        defaultValues {
          name
          id
        }
      }
    }
  }
`;

// region Queries to be able to modify entity settings to test csvMapperSchameAttributes
const ENTITY_SETTINGS_UPDATE = `
  mutation entitySettingsEdit($ids: [ID!]!, $input: [EditInput!]!) {
    entitySettingsFieldPatch(ids: $ids, input: $input) {
      id
    }
  }
`;
const ENTITY_SETTINGS_GET = `
  query getEntitySettingsQuery {
    entitySettings {
      edges {
        node {
          id
          target_type
          attributes_configuration
        }
      }
    }
  }
`;
// endregion

describe('CSV Mapper Resolver', () => {
  let entitySettingStixCoreRel;
  let addedMapper;

  beforeAll(async () => {
    const { data } = await internalAdminQuery(ENTITY_SETTINGS_GET);
    const entitySettings = data.entitySettings.edges.map((e) => e.node);
    entitySettingStixCoreRel = entitySettings.find((setting) => setting.target_type === ABSTRACT_STIX_CORE_RELATIONSHIP);

    await internalAdminQuery(
      ENTITY_SETTINGS_UPDATE,
      {
        ids: [entitySettingStixCoreRel.id],
        input: {
          key: 'attributes_configuration',
          value: JSON.stringify([
            { name: 'description', default_values: ['hello'], mandatory: true }
          ])
        }
      }
    );
  });

  afterAll(async () => {
    await internalAdminQuery(
      ENTITY_SETTINGS_UPDATE,
      {
        ids: [entitySettingStixCoreRel.id],
        input: {
          key: 'attributes_configuration',
          value: entitySettingStixCoreRel.attributes_configuration
        }
      }
    );
  });

  it('should create a mapper', async () => {
    const { data } = await queryAsAdmin({
      query: CREATE_QUERY,
      variables: { input: MAPPER_INPUT },
    });
    const { csvMapperAdd } = data;

    expect(csvMapperAdd).toBeDefined();
    expect(csvMapperAdd.name).toEqual(MAPPER_INPUT.name);
    expect(csvMapperAdd.has_header).toEqual(MAPPER_INPUT.has_header);
    expect(csvMapperAdd.separator).toEqual(MAPPER_INPUT.separator);
    expect(csvMapperAdd.skipLineChar).toEqual(MAPPER_INPUT.skipLineChar);
    addedMapper = csvMapperAdd;
  });

  it('should fail to create a mapper with malformed JSON representations', async () => {
    const { errors } = await queryAsAdmin({
      query: CREATE_QUERY,
      variables: {
        input: {
          ...MAPPER_INPUT,
          representations: '{ invalid // json --',
        }
      },
    });
    expect(errors).toBeDefined();
    expect(errors[0].message).toBe('Could not parse CSV mapper: representations is not a valid JSON');
  });

  it('should fail to create a mapper with invalid representations', async () => {
    const { errors } = await queryAsAdmin({
      query: CREATE_QUERY,
      variables: {
        input: {
          ...MAPPER_INPUT,
          representations: JSON.stringify('{ "id": "test", "type": "InvalidType" }'),
        }
      },
    });
    expect(errors).toBeDefined();
    expect(errors[0].message).toBe('CSV mapper representations is not an array of CsvMapperRepresentation objects');
  });

  it('should retrieve a mapper by internal id', async () => {
    const { data } = await queryAsAdmin({
      query: READ_QUERY,
      variables: { id: addedMapper.id }
    });
    const { csvMapper } = data;

    expect(csvMapper).toBeDefined();
    expect(csvMapper.name).toEqual(MAPPER_INPUT.name);
    expect(csvMapper.has_header).toEqual(MAPPER_INPUT.has_header);
    expect(csvMapper.separator).toEqual(MAPPER_INPUT.separator);
    expect(csvMapper.skipLineChar).toEqual(MAPPER_INPUT.skipLineChar);
  });

  it('should retrieve a mapper by standard id', async () => {
    const { data } = await queryAsAdmin({
      query: READ_QUERY,
      variables: { id: addedMapper.standard_id }
    });
    const { csvMapper } = data;

    expect(csvMapper).toBeDefined();
    expect(csvMapper.name).toEqual(MAPPER_INPUT.name);
    expect(csvMapper.has_header).toEqual(MAPPER_INPUT.has_header);
    expect(csvMapper.separator).toEqual(MAPPER_INPUT.separator);
    expect(csvMapper.skipLineChar).toEqual(MAPPER_INPUT.skipLineChar);
  });

  it('should list all mappers', async () => {
    const { data } = await queryAsAdmin({
      query: LIST_QUERY,
    });
    const csvMappers = data.csvMappers.edges;
    const csvMapper = csvMappers[0].node;

    expect(csvMappers.length).toEqual(1);
    expect(csvMapper).toBeDefined();
    expect(csvMapper.name).toEqual(MAPPER_INPUT.name);
    expect(csvMapper.has_header).toEqual(MAPPER_INPUT.has_header);
    expect(csvMapper.separator).toEqual(MAPPER_INPUT.separator);
    expect(csvMapper.skipLineChar).toEqual(MAPPER_INPUT.skipLineChar);
  });

  it('should extract data from the content', async () => {
    const { data } = await queryAsAdmin({
      query: TEST_QUERY,
      variables: {
        configuration: JSON.stringify(addedMapper),
        content: MAPPER_TEST_CONTENT
      }
    });
    const { csvMapperTest } = data;
    const objects = JSON.parse(csvMapperTest.objects);

    expect(csvMapperTest).toBeDefined();
    expect(csvMapperTest.nbEntities).toEqual(2);
    expect(csvMapperTest.nbRelationships).toEqual(1);
    expect(objects.length).toEqual(3);
    expect(objects.find((o) => o.name === 'morbihan')).toBeDefined();
    expect(objects.find((o) => o.name === 'vador')).toBeDefined();
    expect(objects.find((o) => o.relationship_type === 'targets')).toBeDefined();
  });

  it('should delete a mapper by its ID', async () => {
    const deleteResult = await queryAsAdmin({
      query: DELETE_MUTATION,
      variables: { id: addedMapper.id },
    });
    const { csvMapperDelete } = deleteResult.data;

    const { data } = await queryAsAdmin({
      query: LIST_QUERY,
    });
    const csvMappers = data.csvMappers.edges;

    expect(csvMapperDelete).toBeDefined();
    expect(csvMapperDelete).toEqual(addedMapper.id);
    expect(csvMappers.length).toEqual(0);
  });

  it('should retrieve relationship settings from stix-core-rel', async () => {
    const { data } = await queryAsAdmin({
      query: LIST_SCHEMAS_QUERY,
    });
    const { attributes } = data.csvMapperSchemaAttributes.find((schema) => schema.name === 'related-to');
    const description = attributes.find((attr) => attr.name === 'description');
    expect(description.mandatory).toEqual(true);
    expect(description.defaultValues[0].name).toEqual('hello');
  });
});
