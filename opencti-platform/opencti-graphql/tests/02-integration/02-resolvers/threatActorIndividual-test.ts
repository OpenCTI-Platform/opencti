import gql from 'graphql-tag';
import { describe, expect, it } from 'vitest';
import { queryAsAdmin } from '../../utils/testQuery';
import type { EditInput, EntitySettingEdge, ThreatActorIndividualAddInput } from '../../../src/generated/graphql';
import { EditOperation } from '../../../src/generated/graphql';
import { executionContext, SYSTEM_USER } from '../../../src/utils/access';
import { initCreateEntitySettings } from '../../../src/modules/entitySetting/entitySetting-domain';
import { ENTITY_TYPE_THREAT_ACTOR_INDIVIDUAL } from '../../../src/modules/threatActorIndividual/threatActorIndividual-types';
import type { OverviewLayoutCustomization } from '../../../src/modules/entitySetting/entitySetting-types';
import { resetCacheForEntity } from '../../../src/database/cache';
import { ENTITY_TYPE_SETTINGS } from '../../../src/schema/internalObject';

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
  let threatActorIndividualEntitySettingId: string;
  let defaultTAIOverviewLayoutCustomization: OverviewLayoutCustomization[];

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
  it('should init entity settings', async () => {
    const LIST_QUERY = gql`
      query entitySettings {
        entitySettings {
          edges {
            node {
              id
              target_type
              overview_layout_customization {
                key
                width
                label
              }
            }
          }
        }
      }
    `;
    const context = executionContext('test');
    await initCreateEntitySettings(context, SYSTEM_USER);
    const queryResult = await queryAsAdmin({ query: LIST_QUERY });

    const threatActorIndividualEntitySettingResponse = queryResult.data?.entitySettings.edges
      .find((entitySetting: EntitySettingEdge) => entitySetting.node.target_type === ENTITY_TYPE_THREAT_ACTOR_INDIVIDUAL);
    expect(threatActorIndividualEntitySettingResponse).toBeTruthy();
    // save id info for next tests
    threatActorIndividualEntitySettingId = threatActorIndividualEntitySettingResponse?.node.id;

    expect(threatActorIndividualEntitySettingResponse?.node.overview_layout_customization).toHaveLength(9);
    // save default config for next tests
    defaultTAIOverviewLayoutCustomization = threatActorIndividualEntitySettingResponse?.node.overview_layout_customization as OverviewLayoutCustomization[];
    expect(defaultTAIOverviewLayoutCustomization.every(({ key, width, label }) => !!key && !!width && !!label)).toBe(true);
    const defaultOverviewLayoutCustomizationKeys = [
      'details',
      'basicInformation',
      'demographics',
      'biographics',
      'latestCreatedRelationships',
      'latestContainers',
      'externalReferences',
      'mostRecentHistory',
      'notes',
    ];
    expect(defaultOverviewLayoutCustomizationKeys.every((key) => defaultTAIOverviewLayoutCustomization.map(({ key: widgetKey }) => widgetKey).includes(key))).toEqual(true);
  });
  describe('Overview layout customization', async () => {
    const ENTITY_SETTINGS_UPDATE_QUERY = gql`
      mutation entitySettingsEdit($ids: [ID!]!, $input: [EditInput!]!) {
        entitySettingsFieldPatch(ids: $ids, input: $input) {
          id
          target_type
          overview_layout_customization {
            key
            width
            label
          }
        }
      }
  `;
    it('should update width', async () => {
      // Customize the overview layout width
      const overviewLayoutCustomizationConfiguration: OverviewLayoutCustomization[] = [
        { key: 'details', width: 12, label: 'Entity details' }, // 6 -> 12
        { key: 'basicInformation', width: 12, label: 'Basic information' }, // 6 -> 12
        { key: 'demographics', width: 6, label: 'Demographics' },
        { key: 'biographics', width: 6, label: 'Biographics' },
        { key: 'latestCreatedRelationships', width: 6, label: 'Latest created relationships' },
        { key: 'latestContainers', width: 6, label: 'Latest containers' },
        { key: 'externalReferences', width: 6, label: 'External references' },
        { key: 'mostRecentHistory', width: 6, label: 'Most recent history' },
        { key: 'notes', width: 12, label: 'Notes about this entity' },
      ];
      const entitySettingsUpdateResult = await queryAsAdmin({
        query: ENTITY_SETTINGS_UPDATE_QUERY,
        variables: {
          ids: [threatActorIndividualEntitySettingId],
          input: {
            key: 'overview_layout_customization',
            value: overviewLayoutCustomizationConfiguration,
          }
        }
      });

      expect(
        entitySettingsUpdateResult.data?.entitySettingsFieldPatch?.[0]?.overview_layout_customization
      ).toEqual(
        overviewLayoutCustomizationConfiguration
      );
    });
    it('should update order', async () => {
      // Customize the overview layout order
      const overviewLayoutCustomizationConfiguration: OverviewLayoutCustomization[] = [
        { key: 'basicInformation', width: 6, label: 'Basic information' }, // order + 1
        { key: 'details', width: 6, label: 'Entity details' }, // order - 1
        { key: 'demographics', width: 6, label: 'Demographics' },
        { key: 'biographics', width: 6, label: 'Biographics' },
        { key: 'latestCreatedRelationships', width: 6, label: 'Latest created relationships' },
        { key: 'latestContainers', width: 6, label: 'Latest containers' },
        { key: 'externalReferences', width: 6, label: 'External references' },
        { key: 'mostRecentHistory', width: 6, label: 'Most recent history' },
        { key: 'notes', width: 12, label: 'Notes about this entity' },
      ];
      const entitySettingsUpdateResult = await queryAsAdmin({
        query: ENTITY_SETTINGS_UPDATE_QUERY,
        variables: {
          ids: [threatActorIndividualEntitySettingId],
          input: {
            key: 'overview_layout_customization',
            value: overviewLayoutCustomizationConfiguration,
          }
        }
      });
      expect(
        entitySettingsUpdateResult.data?.entitySettingsFieldPatch?.[0]?.overview_layout_customization
      ).toEqual(
        overviewLayoutCustomizationConfiguration
      );
    });
    // reset entity settings overview_layout_customization
    it('should reset overview_layout_customization', async () => {
      const entitySettingsUpdateResult = await queryAsAdmin({
        query: ENTITY_SETTINGS_UPDATE_QUERY,
        variables: {
          ids: [threatActorIndividualEntitySettingId],
          input: {
            key: 'overview_layout_customization',
            value: [],
          }
        }
      });
      expect(
        entitySettingsUpdateResult.data?.entitySettingsFieldPatch?.[0]?.overview_layout_customization
      ).toEqual(
        defaultTAIOverviewLayoutCustomization
      );
      resetCacheForEntity(ENTITY_TYPE_SETTINGS);
    });
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
      object_path: '/height/0',
      value: [{ measure: 182, date_seen: DATES[0] }],
      operation: EditOperation.Replace,
    };
    const ADD_HEIGHTS: EditInput = {
      key: 'height',
      value: [
        { measure: 189, date_seen: DATES[1] },
        { measure: 190, date_seen: DATES[2] },
      ],
      operation: EditOperation.Add,
    };
    const REPLACE_INDEX_HEIGHT: EditInput = {
      key: 'height',
      object_path: '/height/0',
      value: [{ measure: 183, date_seen: DATES[0] }],
      operation: EditOperation.Replace,
    };
    const REMOVE_INDEX_HEIGHT: EditInput = {
      key: 'height',
      value: [],
      object_path: '/height/2',
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
    expect(threatActorIndividual.height[1]).toEqual(expectedHeights[2]); // 189
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
      object_path: '/height/0/measure',
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
      object_path: '/height',
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
      object_path: '/weight/0',
      value: [{ measure: 183, date_seen: DATES[0] }],
      operation: EditOperation.Replace,
    };
    const REMOVE_INDEX_WEIGHT: EditInput = {
      key: 'weight',
      value: [],
      object_path: '/weight/2',
      operation: EditOperation.Remove,
    };
    const REMOVE_ALL_WEIGHTS: EditInput = {
      key: 'weight',
      value: [],
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
  it('should fail update for invalid input', async () => {
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
