import { describe, expect, it } from 'vitest';
import gql from 'graphql-tag';
import { queryAsAdmin } from '../../utils/testQuery';
import { ENTITY_TYPE_IDENTITY_INDIVIDUAL, ENTITY_TYPE_LOCATION_POSITION, ENTITY_TYPE_VULNERABILITY } from '../../../src/schema/stixDomainObject';
import { ENTITY_TYPE_KILL_CHAIN_PHASE } from '../../../src/schema/stixMetaObject';
import { ENTITY_TYPE_MIGRATION_STATUS } from '../../../src/schema/internalObject';
import { ENTITY_EMAIL_ADDR } from '../../../src/schema/stixCyberObservable';
import { RELATION_PARTICIPATE_TO } from '../../../src/schema/internalRelationship';
import { RELATION_OBJECT_LABEL, RELATION_OPERATING_SYSTEM } from '../../../src/schema/stixRefRelationship';
import { RELATION_HOSTS } from '../../../src/schema/stixCoreRelationship';
import { STIX_SIGHTING_RELATIONSHIP } from '../../../src/schema/stixSightingRelationship';

const RUNTIME_ATTRIBUTES_QUERY = gql`
  query runtimeAttributes(
    $first: Int
    $search: String
    $attributeName: String!
  ) {
    runtimeAttributes(
      first: $first
      search: $search
      attributeName: $attributeName
    ) {
      edges {
        node {
          value
        }
      }
    }
  }
`;

const SCHEMA_ATTRIBUTES_QUERY = gql`
  query schemaAttributeNames($elementType: [String]!) {
    schemaAttributeNames(elementType: $elementType) {
      edges {
        node {
          value
        }
      }
    }
  }
`;

describe('Attribute resolver standard behavior', () => {
  it('should retrieve runtime attribute for an entity', async () => {
    const queryResult = await queryAsAdmin({
      query: RUNTIME_ATTRIBUTES_QUERY,
      variables: { attributeName: 'priority' }
    });
    const attributes = queryResult.data.runtimeAttributes.edges;
    expect(attributes.length).toEqual(0);
  });
  it('should retrieve schema attribute for an object', async () => {
    // Internal Object
    let queryResult = await queryAsAdmin({
      query: SCHEMA_ATTRIBUTES_QUERY,
      variables: { elementType: ENTITY_TYPE_MIGRATION_STATUS }
    });
    let attributes = queryResult.data.schemaAttributeNames.edges.map((edgeNode) => edgeNode.node);
    expect(attributes.length).toEqual(11);
    expect(attributes.map((node) => node.value).includes('entity_type')).toBeTruthy(); // Inherit attribute
    expect(attributes.map((node) => node.value).includes('platformVersion')).toBeTruthy(); // Direct attribute

    // Stix Domain Object
    queryResult = await queryAsAdmin({
      query: SCHEMA_ATTRIBUTES_QUERY,
      variables: { elementType: ENTITY_TYPE_VULNERABILITY }
    });
    attributes = queryResult.data.schemaAttributeNames.edges.map((edgeNode) => edgeNode.node);
    expect(attributes.length).toEqual(28);
    expect(attributes.map((node) => node.value).includes('x_opencti_stix_ids')).toBeTruthy(); // Inherit attribute
    expect(attributes.map((node) => node.value).includes('revoked')).toBeTruthy(); // Inherit attribute
    expect(attributes.map((node) => node.value).includes('description')).toBeTruthy(); // Direct attribute

    // Stix Cyber Observable Object
    queryResult = await queryAsAdmin({ query: SCHEMA_ATTRIBUTES_QUERY, variables: { elementType: ENTITY_EMAIL_ADDR } });
    attributes = queryResult.data.schemaAttributeNames.edges.map((edgeNode) => edgeNode.node);
    expect(attributes.length).toEqual(17);
    expect(attributes.map((node) => node.value).includes('x_opencti_description')).toBeTruthy(); // Inherit attribute
    expect(attributes.map((node) => node.value).includes('display_name')).toBeTruthy(); // Direct attribute

    // Stix Meta Object
    queryResult = await queryAsAdmin({
      query: SCHEMA_ATTRIBUTES_QUERY,
      variables: { elementType: ENTITY_TYPE_KILL_CHAIN_PHASE }
    });
    attributes = queryResult.data.schemaAttributeNames.edges.map((edgeNode) => edgeNode.node);
    expect(attributes.length).toEqual(16);
    expect(attributes.map((node) => node.value).includes('entity_type')).toBeTruthy(); // Inherit attribute
    expect(attributes.map((node) => node.value).includes('created')).toBeTruthy(); // Inherit attribute
    expect(attributes.map((node) => node.value).includes('phase_name')).toBeTruthy(); // Direct attribute

    // Stix Identity Object
    queryResult = await queryAsAdmin({
      query: SCHEMA_ATTRIBUTES_QUERY,
      variables: { elementType: ENTITY_TYPE_IDENTITY_INDIVIDUAL }
    });
    attributes = queryResult.data.schemaAttributeNames.edges.map((edgeNode) => edgeNode.node);
    expect(attributes.length).toEqual(28);
    expect(attributes.map((node) => node.value).includes('lang')).toBeTruthy(); // Inherit attribute
    expect(attributes.map((node) => node.value).includes('contact_information')).toBeTruthy(); // Inherit attribute
    expect(attributes.map((node) => node.value).includes('x_opencti_firstname')).toBeTruthy(); // Direct attribute

    // Stix Location Object
    queryResult = await queryAsAdmin({
      query: SCHEMA_ATTRIBUTES_QUERY,
      variables: { elementType: ENTITY_TYPE_LOCATION_POSITION }
    });
    attributes = queryResult.data.schemaAttributeNames.edges.map((edgeNode) => edgeNode.node);
    expect(attributes.length).toEqual(28);
    expect(attributes.map((node) => node.value).includes('lang')).toBeTruthy(); // Inherit attribute
    expect(attributes.map((node) => node.value).includes('precision')).toBeTruthy(); // Inherit attribute
    expect(attributes.map((node) => node.value).includes('postal_code')).toBeTruthy(); // Direct attribute
  });
  it('should retrieve schema attribute for a relationship', async () => {
    // Internal Relationship
    let queryResult = await queryAsAdmin({
      query: SCHEMA_ATTRIBUTES_QUERY,
      variables: { elementType: RELATION_PARTICIPATE_TO }
    });
    let attributes = queryResult.data.schemaAttributeNames.edges.map((edgeNode) => edgeNode.node);
    expect(attributes.length).toEqual(17);
    expect(attributes.map((node) => node.value).includes('standard_id')).toBeTruthy(); // Inherit attribute
    expect(attributes.map((node) => node.value).includes('i_inference_weight')).toBeTruthy(); // Direct attribute
    // Stix Ref Relationship
    queryResult = await queryAsAdmin({
      query: SCHEMA_ATTRIBUTES_QUERY,
      variables: { elementType: RELATION_OBJECT_LABEL }
    });
    attributes = queryResult.data.schemaAttributeNames.edges.map((edgeNode) => edgeNode.node);
    expect(attributes.length).toEqual(22);
    expect(attributes.map((node) => node.value).includes('created')).toBeTruthy(); // Inherit attribute
    expect(attributes.map((node) => node.value).includes('confidence')).toBeTruthy(); // Direct attribute

    // Stix Core Relationship
    queryResult = await queryAsAdmin({
      query: SCHEMA_ATTRIBUTES_QUERY,
      variables: { elementType: RELATION_HOSTS }
    });
    attributes = queryResult.data.schemaAttributeNames.edges.map((edgeNode) => edgeNode.node);
    expect(attributes.length).toEqual(24);
    expect(attributes.map((node) => node.value).includes('x_opencti_workflow_id')).toBeTruthy(); // Direct attribute

    // Stix Ref Relationship
    queryResult = await queryAsAdmin({
      query: SCHEMA_ATTRIBUTES_QUERY,
      variables: { elementType: RELATION_OPERATING_SYSTEM }
    });
    attributes = queryResult.data.schemaAttributeNames.edges.map((edgeNode) => edgeNode.node);
    expect(attributes.length).toEqual(22);
    expect(attributes.map((node) => node.value).includes('standard_id')).toBeTruthy(); // Inherit attribute
    expect(attributes.map((node) => node.value).includes('revoked')).toBeTruthy(); // Direct attribute

    // Stix Sighting Relationship
    queryResult = await queryAsAdmin({
      query: SCHEMA_ATTRIBUTES_QUERY,
      variables: { elementType: STIX_SIGHTING_RELATIONSHIP }
    });
    attributes = queryResult.data.schemaAttributeNames.edges.map((edgeNode) => edgeNode.node);
    expect(attributes.length).toEqual(26);
    expect(attributes.map((node) => node.value).includes('creator_id')).toBeTruthy(); // Inherit attribute
    expect(attributes.map((node) => node.value).includes('x_opencti_negative')).toBeTruthy(); // Direct attribute
  });
});
