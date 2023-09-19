import gql from "graphql-tag";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { queryAsAdmin } from "../../utils/testQuery";
import type { ThreatActorIndividualAddInput } from "../../../src/generated/graphql";

const READ_QUERY = gql`
  query threatActorIndividual($id: String!) {
    threatActorIndividual(id: $id) {
      id
      name
      description
    }
  }
`;

const REF_COUNTRY = {
  name: 'Test Country',
  id: null,
};
const UPDATED_COUNTRY = {
  name: 'Updated Country',
  id: null,
};
const THREAT_ACTOR: ThreatActorIndividualAddInput = {
  name: "John Doe Test",
  description: "A test threat actor individual",
  gender: "male",
  job_title: "Test actor",
  marital_status: "annulled",
  eye_color: "blue",
  hair_color: "brown",
  height: [{
    height_cm: 183,
    date_seen: "2022-10-10T00:00:00Z"
  }],
  weight: [
    {
      weight_kg: 82,
      date_seen: "2022-10-10T00:00:00Z"
    },
    {
      weight_kg: 81
    }
  ],
  bornIn: null,
  ethnicity: null,
}

const isDate = (value: string) => !isNaN(new Date(value).getTime());

beforeAll(async () => {
  const CREATE_COUNTRY = gql`
    mutation createCountry($input: CountryAddInput!) {
      countryAdd(input: $input) {
        name
        id
      }
    }
  `;
  let result = await queryAsAdmin({
    query: CREATE_COUNTRY,
    variables: { input: { name: REF_COUNTRY.name } },
  });
  const country = result.data?.countryAdd;
  THREAT_ACTOR.bornIn = country.id;
  THREAT_ACTOR.ethnicity = country.id;
  REF_COUNTRY.id = country.id;
  result = await queryAsAdmin({
    query: CREATE_COUNTRY,
    variables: { input: { name: UPDATED_COUNTRY.name } },
  });
  UPDATED_COUNTRY.id = result?.data?.countryAdd?.id;
});

afterAll(async () => {
  const DELETE_COUNTRY = gql`
    mutation deleteCountry($id: ID!) {
      countryEdit(id: $id) { delete }
    }
  `;
  if (REF_COUNTRY.id) {
    await queryAsAdmin({
      query: DELETE_COUNTRY,
      variables: { id: REF_COUNTRY.id },
    });
  }
  if (UPDATED_COUNTRY.id) {
    await queryAsAdmin({
      query: DELETE_COUNTRY,
      variables: { id: UPDATED_COUNTRY.id },
    });
  }
});

describe('Threat actor individual resolver standard behavior', () => {
  let threatActorIndividualInternalId: string;
  const threatActorIndividualStixId = 'threat-actor--213557a7-30bf-565f-bd8e-71d4cf6f3c2d';
  it('should create threat actor individual', async () => {
    const CREATE_QUERY = gql`
      mutation threatActorIndividualAdd($input: ThreatActorIndividualAddInput!) {
        threatActorIndividualAdd(input: $input) {
          id
          name
          description
          gender
          job_title
          marital_status
          eye_color
          hair_color
          height {
            height_cm
            date_seen
          }
          weight {
            weight_kg
            date_seen
          }
          bornIn {
            name
          }
          ethnicity {
            name
          }
        }
      }
    `;
    const threatActorIndividual = await queryAsAdmin({
      query: CREATE_QUERY,
      variables: { input: THREAT_ACTOR },
    });
    expect(threatActorIndividual?.data).not.toBeNull();
    expect(threatActorIndividual.data?.threatActorIndividualAdd).not.toBeNull();
    const actual = threatActorIndividual.data?.threatActorIndividualAdd;
    const _expectField = (field: keyof ThreatActorIndividualAddInput) => {
      expect(actual[field]).toEqual(THREAT_ACTOR[field]);
    }
    _expectField('name');
    _expectField('description');
    _expectField('gender');
    _expectField('job_title');
    _expectField('marital_status');
    _expectField('eye_color');
    _expectField('hair_color');
    expect(actual.height.length)
      .toEqual(1);
    expect(actual.weight.length)
      .toEqual(2);
    expect(actual.bornIn?.name)
      .toEqual(REF_COUNTRY.name)
    expect(actual.ethnicity?.name)
      .toEqual(REF_COUNTRY.name)
    threatActorIndividualInternalId = actual.id;
  });
  it('should update threat actor individual details', async () => {
    const UPDATE_QUERY = gql`
      mutation threatActorIndividualEditDetails($id: ID!, $input: [EditInput]!) {
        threatActorIndividualFieldPatch(id:$id, input:$input) {
          first_seen
          last_seen
          sophistication
          resource_level
          roles
          primary_motivation
          secondary_motivations
          personal_motivations
          goals
        }
      }
    `;
    const UPDATES = [
      { key: 'first_seen', value: '2022-10-10T00:00:00.000Z' },
      { key: 'last_seen', value: '2022-10-12T00:00:00.000Z' },
      { key: 'sophistication', value: 'advanced' },
      { key: 'resource_level', value: 'club' },
      { key: 'roles', value: ['agent', 'director'] },
      { key: 'primary_motivation', value: 'notoriety' },
      { key: 'secondary_motivations', value: ['coercion', 'ideology'] },
      { key: 'personal_motivations', value: ['personal-gain', 'personal-satisfaction'] },
      { key: 'goals', value: ['property', 'temerity'] },
    ];
    const result = await queryAsAdmin({
      query: UPDATE_QUERY,
      variables: { id: threatActorIndividualInternalId, input: UPDATES },
    });
    const threatActorIndividual = result.data?.threatActorIndividualFieldPatch;
    expect(threatActorIndividual).not.toBeNull();
    expect(threatActorIndividual).toBeDefined();
    UPDATES.forEach(({ key, value }) => {
      expect(threatActorIndividual[key]).not.toBeNull();
      expect(threatActorIndividual[key]).toBeDefined();
      if (Array.isArray(value)) {
        expect(threatActorIndividual[key]).toHaveLength(value.length);
        expect(threatActorIndividual[key]).toStrictEqual(value);
      } else if (isDate(value)) {
        expect(threatActorIndividual[key].toISOString()).toEqual(value);
      } else {
        expect(threatActorIndividual[key]).toEqual(value);
      }
    })
  });
  it('should update threat actor individual demographics', async () => {
    const UPDATE_QUERY = gql`
      mutation threatActorIndividualEditDemographics($id: ID!, $input: [EditInput]!) {
        threatActorIndividualFieldPatch(id:$id, input:$input) {
          bornIn {
            name
          }
          ethnicity {
            name
          }
          date_of_birth
          marital_status
          gender
          job_title
        }
      }
    `;
    const UPDATES = [
      { key: 'bornIn', value: UPDATED_COUNTRY.id },
      { key: 'ethnicity', value: UPDATED_COUNTRY.id },
      { key: 'date_of_birth', value: '1998-01-10T00:00:00.000Z' },
      { key: 'marital_status', value: 'annulled' },
      { key: 'gender', value: 'male' },
      { key: 'job_title', value: 'A test hacker' },
    ];
    const result = await queryAsAdmin({
      query: UPDATE_QUERY,
      variables: { id: threatActorIndividualInternalId, input: UPDATES },
    });
    const threatActorIndividual = result.data?.threatActorIndividualFieldPatch;
    expect(threatActorIndividual).not.toBeNull();
    expect(threatActorIndividual).toBeDefined();
    expect(threatActorIndividual.bornIn?.name).toEqual(UPDATED_COUNTRY.name);
    expect(threatActorIndividual.ethnicity?.name).toEqual(UPDATED_COUNTRY.name);
    expect(threatActorIndividual.date_of_birth.toISOString()).toEqual('1998-01-10T00:00:00.000Z');
    expect(threatActorIndividual.marital_status).toEqual('annulled');
    expect(threatActorIndividual.gender).toEqual('male');
    expect(threatActorIndividual.job_title).toEqual('A test hacker');
  });
  it('should update threat actor individual core relationships', async () => {
    const getCoreRelationships = gql`
      query threatActorIndividiualGetCoreRelationships($id: String!) {
        threatActorIndividual(id:$id) {
          stixCoreRelationships {
            edges {
              node {
                relationship_type
                toId
              }
            }
          }
        }
      }
    `;
    const addCoreRelationship = gql`
      mutation threatActorIndividualAddCoreRelationship($input: StixCoreRelationshipAddInput!) {
        stixCoreRelationshipAdd(input: $input) {
          id
        }
      }
    `;
    const relationships = [
      'resides-in',
      'citizen-of',
      'national-of',
    ]
    await Promise.all(relationships.map(relationship_type => queryAsAdmin({
      query: addCoreRelationship,
      variables: { input: {
        fromId: threatActorIndividualInternalId,
        toId: REF_COUNTRY.id,
        relationship_type,
      }}
    })));
    const { data } = await queryAsAdmin({
      query: getCoreRelationships,
      variables: { id: threatActorIndividualInternalId },
    });
    expect(data?.threatActorIndividual?.stixCoreRelationships?.edges).toHaveLength(3);
    const stixCoreRelationships = data?.threatActorIndividual
      ?.stixCoreRelationships?.edges?.map((
        { node }: { node : { relationship_type: string, toId: string }}
      ) => ({ ...node }));
    // expect(stixCoreRelationships).toHaveLength(3);
    relationships.forEach(relationship_type => expect(stixCoreRelationships)
      .toContainEqual({
        relationship_type,
        toId: REF_COUNTRY.id,
      })
    );
  });
  it('should update threat actor individual biographics', async () => {
    const UPDATE_QUERY = gql`
      mutation threatActorIndividualEditBiographics($id: ID!, $input: [EditInput]!) {
        threatActorIndividualFieldPatch(id:$id, input:$input) {
          eye_color
          hair_color
        }
      }
    `;
    const UPDATES = [
      { key: 'eye_color', value: 'hazel' },
      { key: 'hair_color', value: 'brown' },
    ];
    const result = await queryAsAdmin({
      query: UPDATE_QUERY,
      variables: { id: threatActorIndividualInternalId, input: UPDATES },
    });
    const threatActorIndividual = result.data?.threatActorIndividualFieldPatch;
    expect(threatActorIndividual).not.toBeNull();
    expect(threatActorIndividual).toBeDefined();
    expect(threatActorIndividual.eye_color).toEqual('hazel');
    expect(threatActorIndividual.hair_color).toEqual('brown');
  });
  it('should update threat actor individual heights', async () => {
    const HEIGHT_EDIT = gql`
      mutation threatActorIndividualHeightEdit($id: ID!, $input: HeightTupleInput!) {
        threatActorIndividualHeightEdit(id:$id, input:$input) {
          height {
            height_cm
            date_seen
          }
        }
      }
    `;
    const DATES = [
      '2017-11-06T00:00:00.000Z',
      '2019-12-10T00:00:00.000Z',
      '2019-12-15T00:00:00.000Z',
    ];
    const REPLACE_ALL_HEIGHT = {
      values: [{ height_cm: 182, date_seen: DATES[0] }],
      operation: 'replace',
    };
    const ADD_HEIGHTS = {
      values: [
        { height_cm: 190, date_seen: DATES[2] },
        { height_cm: 189, date_seen: DATES[1] },
      ],
      operation: 'add',
    };
    const REPLACE_INDEX_HEIGHT = {
      values: [{ height_cm: 183, date_seen: DATES[0] }],
      index: 0,
      operation: 'replace',
    };
    const REMOVE_INDEX_HEIGHT = {
      index: 1,
      operation: 'remove',
    };
    const REMOVE_ALL_HEIGHTS = {
      operation: 'remove',
    };
    const expectedHeights = [
      { height_cm: 182, date_seen: new Date(DATES[0]) },
      { height_cm: 183, date_seen: new Date(DATES[0]) },
      { height_cm: 189, date_seen: new Date(DATES[1]) },
      { height_cm: 190, date_seen: new Date(DATES[2]) },
    ];

    const replaceAll = await queryAsAdmin({
      query: HEIGHT_EDIT,
      variables: { id: threatActorIndividualInternalId, input: REPLACE_ALL_HEIGHT },
    });
    let threatActorIndividual = replaceAll?.data?.threatActorIndividualHeightEdit;
    expect(threatActorIndividual).not.toBeNull();
    expect(threatActorIndividual).toBeDefined();
    expect(threatActorIndividual.height).toHaveLength(1);
    expect(threatActorIndividual.height[0]).toEqual(expectedHeights[0]);

    const addHeights = await queryAsAdmin({
      query: HEIGHT_EDIT,
      variables: { id: threatActorIndividualInternalId, input: ADD_HEIGHTS },
    });
    threatActorIndividual = addHeights?.data?.threatActorIndividualHeightEdit;
    expect(threatActorIndividual).not.toBeNull();
    expect(threatActorIndividual).toBeDefined();
    expect(threatActorIndividual?.height).toHaveLength(3);
    expect(threatActorIndividual.height[0]).toEqual(expectedHeights[0]);
    expect(threatActorIndividual.height[1]).toEqual(expectedHeights[2]);
    expect(threatActorIndividual.height[2]).toEqual(expectedHeights[3]);

    const replaceIndex = await queryAsAdmin({
      query: HEIGHT_EDIT,
      variables: { id: threatActorIndividualInternalId, input: REPLACE_INDEX_HEIGHT },
    });
    threatActorIndividual = replaceIndex?.data?.threatActorIndividualHeightEdit;
    expect(threatActorIndividual).not.toBeNull();
    expect(threatActorIndividual).toBeDefined();
    expect(threatActorIndividual.height).toHaveLength(3);
    expect(threatActorIndividual.height[0]).toEqual(expectedHeights[1]);
    expect(threatActorIndividual.height[1]).toEqual(expectedHeights[2]);
    expect(threatActorIndividual.height[2]).toEqual(expectedHeights[3]);

    const removeIndex = await queryAsAdmin({
      query: HEIGHT_EDIT,
      variables: { id: threatActorIndividualInternalId, input: REMOVE_INDEX_HEIGHT },
    });
    threatActorIndividual = removeIndex?.data?.threatActorIndividualHeightEdit;
    expect(threatActorIndividual).not.toBeNull();
    expect(threatActorIndividual).toBeDefined();
    expect(threatActorIndividual.height).toHaveLength(2);
    expect(threatActorIndividual.height[0]).toEqual(expectedHeights[1]);
    expect(threatActorIndividual.height[1]).toEqual(expectedHeights[3]);
    
    const removeAll = await queryAsAdmin({
      query: HEIGHT_EDIT,
      variables: { id: threatActorIndividualInternalId, input: REMOVE_ALL_HEIGHTS },
    });
    threatActorIndividual = removeAll?.data?.threatActorIndividualHeightEdit;
    expect(threatActorIndividual).not.toBeNull();
    expect(threatActorIndividual).toBeDefined();
    expect(threatActorIndividual.height).toHaveLength(0);
  });
  it('should update threat actor individual weight', async () => {
    const WEIGHT_EDIT = gql`
      mutation threatActorIndividualWeightEdit($id: ID!, $input: WeightTupleInput!) {
        threatActorIndividualWeightEdit(id:$id, input:$input) {
          weight {
            weight_kg
            date_seen
          }
        }
      }
    `;
    const DATES = [
      '2017-11-06T00:00:00.000Z',
      '2019-12-10T00:00:00.000Z',
      '2019-12-15T00:00:00.000Z',
    ];
    const REPLACE_ALL_WEIGHT = {
      values: [{ weight_kg: 182, date_seen: DATES[0] }],
      operation: 'replace',
    };
    const ADD_WEIGHTS = {
      values: [
        { weight_kg: 190, date_seen: DATES[2] },
        { weight_kg: 189, date_seen: DATES[1] },
      ],
      operation: 'add',
    };
    const REPLACE_INDEX_WEIGHT = {
      values: [{ weight_kg: 183, date_seen: DATES[0] }],
      index: 0,
      operation: 'replace',
    };
    const REMOVE_INDEX_WEIGHT = {
      index: 1,
      operation: 'remove',
    };
    const REMOVE_ALL_WEIGHTS = {
      operation: 'remove',
    };
    const expectedWeights = [
      { weight_kg: 182, date_seen: new Date(DATES[0]) },
      { weight_kg: 183, date_seen: new Date(DATES[0]) },
      { weight_kg: 189, date_seen: new Date(DATES[1]) },
      { weight_kg: 190, date_seen: new Date(DATES[2]) },
    ];

    const replaceAll = await queryAsAdmin({
      query: WEIGHT_EDIT,
      variables: { id: threatActorIndividualInternalId, input: REPLACE_ALL_WEIGHT },
    });
    let threatActorIndividual = replaceAll?.data?.threatActorIndividualWeightEdit;
    expect(threatActorIndividual).not.toBeNull();
    expect(threatActorIndividual).toBeDefined();
    expect(threatActorIndividual.weight).toHaveLength(1);
    expect(threatActorIndividual.weight[0]).toEqual(expectedWeights[0]);

    const addHeights = await queryAsAdmin({
      query: WEIGHT_EDIT,
      variables: { id: threatActorIndividualInternalId, input: ADD_WEIGHTS },
    });
    threatActorIndividual = addHeights?.data?.threatActorIndividualWeightEdit;
    expect(threatActorIndividual).not.toBeNull();
    expect(threatActorIndividual).toBeDefined();
    expect(threatActorIndividual?.weight).toHaveLength(3);
    expect(threatActorIndividual.weight[0]).toEqual(expectedWeights[0]);
    expect(threatActorIndividual.weight[1]).toEqual(expectedWeights[2]);
    expect(threatActorIndividual.weight[2]).toEqual(expectedWeights[3]);

    const replaceIndex = await queryAsAdmin({
      query: WEIGHT_EDIT,
      variables: { id: threatActorIndividualInternalId, input: REPLACE_INDEX_WEIGHT },
    });
    threatActorIndividual = replaceIndex?.data?.threatActorIndividualWeightEdit;
    expect(threatActorIndividual).not.toBeNull();
    expect(threatActorIndividual).toBeDefined();
    expect(threatActorIndividual.weight).toHaveLength(3);
    expect(threatActorIndividual.weight[0]).toEqual(expectedWeights[1]);
    expect(threatActorIndividual.weight[1]).toEqual(expectedWeights[2]);
    expect(threatActorIndividual.weight[2]).toEqual(expectedWeights[3]);

    const removeIndex = await queryAsAdmin({
      query: WEIGHT_EDIT,
      variables: { id: threatActorIndividualInternalId, input: REMOVE_INDEX_WEIGHT },
    });
    threatActorIndividual = removeIndex?.data?.threatActorIndividualWeightEdit;
    expect(threatActorIndividual).not.toBeNull();
    expect(threatActorIndividual).toBeDefined();
    expect(threatActorIndividual.weight).toHaveLength(2);
    expect(threatActorIndividual.weight[0]).toEqual(expectedWeights[1]);
    expect(threatActorIndividual.weight[1]).toEqual(expectedWeights[3]);
    
    const removeAll = await queryAsAdmin({
      query: WEIGHT_EDIT,
      variables: { id: threatActorIndividualInternalId, input: REMOVE_ALL_WEIGHTS },
    });
    threatActorIndividual = removeAll?.data?.threatActorIndividualWeightEdit;
    expect(threatActorIndividual).not.toBeNull();
    expect(threatActorIndividual).toBeDefined();
    expect(threatActorIndividual.weight).toHaveLength(0);
  });
  it('should delete threat actor individual', async () => {
    const DELETE_QUERY = gql`
      mutation threatActorIndividualDelete($id: ID!) {
        threatActorIndividualDelete(id: $id)
      }
    `;
    await queryAsAdmin({
      query: DELETE_QUERY,
      variables: { id: threatActorIndividualInternalId },
    });
    const queryResult = await queryAsAdmin({
      query: READ_QUERY,
      variables: { id: threatActorIndividualStixId },
    });
    expect(queryResult).not.toBeNull();
    expect(queryResult.data?.threatActorIndividual).toBeNull();
  });
});