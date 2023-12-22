import gql from 'graphql-tag';
import { describe, expect, it } from 'vitest';
import { queryAsAdmin } from '../../utils/testQuery';
import type { EditInput, ThreatActorIndividualAddInput } from '../../../src/generated/graphql';
import { EditOperation } from '../../../src/generated/graphql';

const READ_QUERY = gql`
  query threatActorIndividual($id: String!) {
    threatActorIndividual(id: $id) {
      id
      name
      description
    }
  }
`;

const threatActorIndividualInternalId = 'threat-actor--9a104727-897b-54ec-8fb8-2f757f81ceec';

const THREAT_ACTOR: ThreatActorIndividualAddInput = {
  name: 'John Doe Test',
  description: 'A test threat actor individual',
  gender: 'male',
  job_title: 'Test actor',
  marital_status: 'annulled',
  eye_color: 'blue',
  hair_color: 'brown',
  height: [{
    measure: 183,
    date_seen: '2022-10-10T00:00:00Z'
  }],
  weight: [
    {
      measure: 82,
      date_seen: '2022-10-10T00:00:00Z'
    },
    {
      measure: 81,
      date_seen: '2022-10-10T00:00:00Z'
    }
  ],
};

const isDate = (value: string) => !Number.isNaN(new Date(value).getTime());

describe('Threat actor individual resolver standard behavior', () => {
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
            measure
            date_seen
          }
          weight {
            measure
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
    };
    _expectField('name');
    _expectField('description');
    _expectField('gender');
    _expectField('job_title');
    _expectField('marital_status');
    _expectField('eye_color');
    _expectField('hair_color');
    expect(actual.height.length).toEqual(1);
    expect(actual.weight.length).toEqual(2);
    expect(actual.bornIn).toBeNull();
    expect(actual.ethnicity).toBeNull();
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
    });
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
      { key: 'bornIn', value: 'location--5acd8b26-51c2-4608-86ed-e9edd43ad971' },
      { key: 'ethnicity', value: 'location--5acd8b26-51c2-4608-86ed-e9edd43ad971' },
      { key: 'date_of_birth', value: '1998-01-10T00:00:00.000Z' },
      { key: 'marital_status', value: 'annulled' },
      { key: 'gender', value: 'male' },
      { key: 'job_title', value: 'A test hacker' },
    ];
    const result = await queryAsAdmin({
      query: UPDATE_QUERY,
      variables: { id: threatActorIndividualInternalId, input: UPDATES },
    });
    console.log(JSON.stringify(result));
    const threatActorIndividual = result.data?.threatActorIndividualFieldPatch;
    expect(threatActorIndividual).not.toBeNull();
    expect(threatActorIndividual).toBeDefined();
    expect(threatActorIndividual.bornIn?.name).toEqual('France');
    expect(threatActorIndividual.ethnicity?.name).toEqual('France');
    expect(threatActorIndividual.date_of_birth.toISOString()).toEqual('1998-01-10T00:00:00.000Z');
    expect(threatActorIndividual.marital_status).toEqual('annulled');
    expect(threatActorIndividual.gender).toEqual('male');
    expect(threatActorIndividual.job_title).toEqual('A test hacker');
  });
  it('should update threat actor individual core relationships', async () => {
    const getCoreRelationships = gql`
      query threatActorIndivididualGetCoreRelationships($id: String!) {
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
    ];
    await Promise.all(relationships.map((relationship_type) => queryAsAdmin({
      query: addCoreRelationship,
      variables: { input: {
        fromId: threatActorIndividualInternalId,
        toId: 'location--5acd8b26-51c2-4608-86ed-e9edd43ad971',
        relationship_type,
      } }
    })));
    const { data } = await queryAsAdmin({
      query: getCoreRelationships,
      variables: { id: threatActorIndividualInternalId },
    });
    expect(data?.threatActorIndividual?.stixCoreRelationships?.edges).toHaveLength(3);
    const stixCoreRelationships = data?.threatActorIndividual
      ?.stixCoreRelationships?.edges?.map((
        { node }: { node : { relationship_type: string, toId: string } }
      ) => ({ ...node }));
    expect(stixCoreRelationships).toHaveLength(3);
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
      mutation threatActorIndividualHeightEdit($id: ID!, $input: [EditInput]!) {
        threatActorIndividualFieldPatch(id:$id, input:$input) {
          height {
            measure
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
    const REPLACE_ALL_HEIGHT: EditInput = {
      key: 'height',
      object_path: '[0]',
      value: [{ measure: 182, date_seen: DATES[0] }],
      operation: EditOperation.Replace,
    };
    const ADD_HEIGHTS: EditInput = {
      key: 'height',
      value: [
        { measure: 190, date_seen: DATES[2] },
        { measure: 189, date_seen: DATES[1] },
      ],
      operation: EditOperation.Add,
    };
    const REPLACE_INDEX_HEIGHT: EditInput = {
      key: 'height',
      object_path: '[0]',
      value: [{ measure: 183, date_seen: DATES[0] }],
      operation: EditOperation.Replace,
    };
    const REMOVE_INDEX_HEIGHT: EditInput = {
      key: 'height',
      value: [],
      object_path: '[2]',
      operation: EditOperation.Remove,
    };

    const expectedHeights = [
      { measure: 182, date_seen: new Date(DATES[0]) }, // 0
      { measure: 183, date_seen: new Date(DATES[0]) }, // 1
      { measure: 189, date_seen: new Date(DATES[1]) }, // 2
      { measure: 190, date_seen: new Date(DATES[2]) }, // 3
    ];

    const replaceAll = await queryAsAdmin({
      query: HEIGHT_EDIT,
      variables: { id: threatActorIndividualInternalId, input: [REPLACE_ALL_HEIGHT] },
    });
    console.log(JSON.stringify(replaceAll));
    let threatActorIndividual = replaceAll?.data?.threatActorIndividualFieldPatch;
    expect(threatActorIndividual).not.toBeNull();
    expect(threatActorIndividual).toBeDefined();
    expect(threatActorIndividual.height).toHaveLength(1);
    expect(threatActorIndividual.height[0]).toEqual(expectedHeights[0]);

    const addHeights = await queryAsAdmin({
      query: HEIGHT_EDIT,
      variables: { id: threatActorIndividualInternalId, input: [ADD_HEIGHTS] },
    });
    threatActorIndividual = addHeights?.data?.threatActorIndividualFieldPatch;
    expect(threatActorIndividual).not.toBeNull();
    expect(threatActorIndividual).toBeDefined();
    expect(threatActorIndividual?.height).toHaveLength(3);
    expect(threatActorIndividual.height[0]).toEqual(expectedHeights[0]); // 182
    expect(threatActorIndividual.height[1]).toEqual(expectedHeights[2]); // 189
    expect(threatActorIndividual.height[2]).toEqual(expectedHeights[3]); // 190

    const replaceIndex = await queryAsAdmin({
      query: HEIGHT_EDIT,
      variables: { id: threatActorIndividualInternalId, input: [REPLACE_INDEX_HEIGHT] },
    });
    threatActorIndividual = replaceIndex?.data?.threatActorIndividualFieldPatch;
    expect(threatActorIndividual).not.toBeNull();
    expect(threatActorIndividual).toBeDefined();
    expect(threatActorIndividual.height).toHaveLength(3);
    expect(threatActorIndividual.height[0]).toEqual(expectedHeights[1]); // 183
    expect(threatActorIndividual.height[1]).toEqual(expectedHeights[2]); // 189
    expect(threatActorIndividual.height[2]).toEqual(expectedHeights[3]); // 190

    const removeIndex = await queryAsAdmin({
      query: HEIGHT_EDIT,
      variables: { id: threatActorIndividualInternalId, input: [REMOVE_INDEX_HEIGHT] },
    });
    threatActorIndividual = removeIndex?.data?.threatActorIndividualFieldPatch;
    expect(threatActorIndividual).not.toBeNull();
    expect(threatActorIndividual).toBeDefined();
    expect(threatActorIndividual.height).toHaveLength(2);
    expect(threatActorIndividual.height[0]).toEqual(expectedHeights[1]); // 183
    expect(threatActorIndividual.height[1]).toEqual(expectedHeights[3]); // 190
  });
  it('should update partial height', async () => {
    const HEIGHT_EDIT = gql`
          mutation threatActorIndividualHeightEdit($id: ID!, $input: [EditInput]!) {
            threatActorIndividualFieldPatch(id:$id, input:$input) {
              height {
                measure
                date_seen
              }
            }
          }
        `;
    const REPLACE_MEASURE_ONLY: EditInput = {
      key: 'height',
      object_path: '[0].measure',
      value: [283],
      operation: EditOperation.Replace,
    };
    const replaceMeasure = await queryAsAdmin({
      query: HEIGHT_EDIT,
      variables: { id: threatActorIndividualInternalId, input: [REPLACE_MEASURE_ONLY] },
    });
    const threatActorIndividual = replaceMeasure?.data?.threatActorIndividualFieldPatch;
    expect(threatActorIndividual).not.toBeNull();
    expect(threatActorIndividual).toBeDefined();
    expect(threatActorIndividual.height).toHaveLength(2);
    expect(threatActorIndividual.height[0].measure).toBe(283);
  });
  it('should remove all height', async () => {
    const HEIGHT_EDIT = gql`
      mutation threatActorIndividualHeightEdit($id: ID!, $input: [EditInput]!) {
        threatActorIndividualFieldPatch(id:$id, input:$input) {
          height {
            measure
            date_seen
          }
        }
      }
    `;
    const REMOVE_ALL_HEIGHTS: EditInput = {
      key: 'height',
      value: [],
      object_path: '[*]',
      operation: EditOperation.Remove,
    };
    const removeAll = await queryAsAdmin({
      query: HEIGHT_EDIT,
      variables: { id: threatActorIndividualInternalId, input: [REMOVE_ALL_HEIGHTS] },
    });
    const threatActorIndividual = removeAll?.data?.threatActorIndividualFieldPatch;
    expect(threatActorIndividual).not.toBeNull();
    expect(threatActorIndividual).toBeDefined();
    expect(threatActorIndividual.height).toHaveLength(0);
  });
  it('should update threat actor individual weight', async () => {
    const WEIGHT_EDIT = gql`
      mutation threatActorIndividualWeightEdit($id: ID!, $input: [EditInput]!) {
        threatActorIndividualFieldPatch(id:$id, input:$input) {
          weight {
            measure
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
    const REPLACE_ALL_WEIGHT: EditInput = {
      key: 'weight',
      value: [{ measure: 182, date_seen: DATES[0] }],
      operation: EditOperation.Replace,
    };
    const ADD_WEIGHTS: EditInput = {
      key: 'weight',
      value: [
        { measure: 190, date_seen: DATES[2] },
        { measure: 189, date_seen: DATES[1] },
      ],
      operation: EditOperation.Add,
    };
    const REPLACE_INDEX_WEIGHT: EditInput = {
      key: 'weight',
      object_path: '[0]',
      value: [{ measure: 183, date_seen: DATES[0] }],
      operation: EditOperation.Replace,
    };
    const REMOVE_INDEX_WEIGHT: EditInput = {
      key: 'weight',
      value: [],
      object_path: '[2]',
      operation: EditOperation.Remove,
    };
    const REMOVE_ALL_WEIGHTS: EditInput = {
      key: 'weight',
      value: [],
      object_path: '[*]',
      operation: EditOperation.Remove,
    };
    const expectedWeights = [
      { measure: 182, date_seen: new Date(DATES[0]) }, // 0
      { measure: 183, date_seen: new Date(DATES[0]) }, // 1
      { measure: 189, date_seen: new Date(DATES[1]) }, // 2
      { measure: 190, date_seen: new Date(DATES[2]) }, // 3
    ];

    const replaceAll = await queryAsAdmin({
      query: WEIGHT_EDIT,
      variables: { id: threatActorIndividualInternalId, input: [REPLACE_ALL_WEIGHT] },
    });
    let threatActorIndividual = replaceAll?.data?.threatActorIndividualFieldPatch;
    expect(threatActorIndividual).not.toBeNull();
    expect(threatActorIndividual).toBeDefined();
    expect(threatActorIndividual.weight).toHaveLength(1);
    expect(threatActorIndividual.weight[0]).toEqual(expectedWeights[0]);

    const addHeights = await queryAsAdmin({
      query: WEIGHT_EDIT,
      variables: { id: threatActorIndividualInternalId, input: [ADD_WEIGHTS] },
    });
    threatActorIndividual = addHeights?.data?.threatActorIndividualFieldPatch;
    expect(threatActorIndividual).not.toBeNull();
    expect(threatActorIndividual).toBeDefined();
    expect(threatActorIndividual?.weight).toHaveLength(3);
    expect(threatActorIndividual.weight[0]).toEqual(expectedWeights[0]);
    expect(threatActorIndividual.weight[1]).toEqual(expectedWeights[2]);
    expect(threatActorIndividual.weight[2]).toEqual(expectedWeights[3]);

    const replaceIndex = await queryAsAdmin({
      query: WEIGHT_EDIT,
      variables: { id: threatActorIndividualInternalId, input: [REPLACE_INDEX_WEIGHT] },
    });
    threatActorIndividual = replaceIndex?.data?.threatActorIndividualFieldPatch;
    expect(threatActorIndividual).not.toBeNull();
    expect(threatActorIndividual).toBeDefined();
    expect(threatActorIndividual.weight).toHaveLength(3);
    expect(threatActorIndividual.weight[0]).toEqual(expectedWeights[1]);
    expect(threatActorIndividual.weight[1]).toEqual(expectedWeights[2]);
    expect(threatActorIndividual.weight[2]).toEqual(expectedWeights[3]);

    const removeIndex = await queryAsAdmin({
      query: WEIGHT_EDIT,
      variables: { id: threatActorIndividualInternalId, input: [REMOVE_INDEX_WEIGHT] },
    });
    threatActorIndividual = removeIndex?.data?.threatActorIndividualFieldPatch;
    expect(threatActorIndividual).not.toBeNull();
    expect(threatActorIndividual).toBeDefined();
    expect(threatActorIndividual.weight).toHaveLength(2);
    expect(threatActorIndividual.weight[0]).toEqual(expectedWeights[1]);
    expect(threatActorIndividual.weight[1]).toEqual(expectedWeights[3]);

    const removeAll = await queryAsAdmin({
      query: WEIGHT_EDIT,
      variables: { id: threatActorIndividualInternalId, input: [REMOVE_ALL_WEIGHTS] },
    });
    threatActorIndividual = removeAll?.data?.threatActorIndividualFieldPatch;
    expect(threatActorIndividual).not.toBeNull();
    expect(threatActorIndividual).toBeDefined();
    expect(threatActorIndividual.weight).toHaveLength(0);
  });
  it.skip('should fail update for invalid input', async () => {
    const WEIGHT_EDIT = gql`
      mutation threatActorIndividualWeightEdit($id: ID!, $input: [EditInput]!) {
        threatActorIndividualFieldPatch(id:$id, input:$input) {
          weight {
            measure
            date_seen
          }
        }
      }
    `;
    const ADD_WEIGHTS: EditInput = {
      key: 'weight',
      value: [
        { measure: 190, date_seen: '2017-11-06T00:00:00.000Z' },
        { measure: 189, date_seen_invalid: '2017-11-06T00:00:00.000Z' },
      ],
      operation: EditOperation.Add,
    };
    const addHeights = await queryAsAdmin({
      query: WEIGHT_EDIT,
      variables: { id: threatActorIndividualInternalId, input: [ADD_WEIGHTS] },
    });
    expect(addHeights?.data?.threatActorIndividualFieldPatch).toBeNull();
    expect(addHeights?.errors?.length).toBe(1);
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
      variables: { id: threatActorIndividualInternalId },
    });
    expect(queryResult).not.toBeNull();
    expect(queryResult.data?.threatActorIndividual).toBeNull();
  });
});
