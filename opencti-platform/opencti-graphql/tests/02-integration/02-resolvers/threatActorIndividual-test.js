var __awaiter = (this && this.__awaiter) || function (thisArg, _arguments, P, generator) {
    function adopt(value) { return value instanceof P ? value : new P(function (resolve) { resolve(value); }); }
    return new (P || (P = Promise))(function (resolve, reject) {
        function fulfilled(value) { try { step(generator.next(value)); } catch (e) { reject(e); } }
        function rejected(value) { try { step(generator["throw"](value)); } catch (e) { reject(e); } }
        function step(result) { result.done ? resolve(result.value) : adopt(result.value).then(fulfilled, rejected); }
        step((generator = generator.apply(thisArg, _arguments || [])).next());
    });
};
import gql from 'graphql-tag';
import { describe, expect, it } from 'vitest';
import { queryAsAdmin } from '../../utils/testQuery';
import { EditOperation } from '../../../src/generated/graphql';
const READ_QUERY = gql `
  query threatActorIndividual($id: String!) {
    threatActorIndividual(id: $id) {
      id
      name
      description
    }
  }
`;
const threatActorIndividualInternalId = 'threat-actor--9a104727-897b-54ec-8fb8-2f757f81ceec';
const THREAT_ACTOR = {
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
const isDate = (value) => !Number.isNaN(new Date(value).getTime());
describe('Threat actor individual resolver standard behavior', () => {
    it('should create threat actor individual', () => __awaiter(void 0, void 0, void 0, function* () {
        var _a, _b;
        const CREATE_QUERY = gql `
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
        const threatActorIndividual = yield queryAsAdmin({
            query: CREATE_QUERY,
            variables: { input: THREAT_ACTOR },
        });
        expect(threatActorIndividual === null || threatActorIndividual === void 0 ? void 0 : threatActorIndividual.data).not.toBeNull();
        expect((_a = threatActorIndividual.data) === null || _a === void 0 ? void 0 : _a.threatActorIndividualAdd).not.toBeNull();
        const actual = (_b = threatActorIndividual.data) === null || _b === void 0 ? void 0 : _b.threatActorIndividualAdd;
        const _expectField = (field) => {
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
    }));
    it('should update threat actor individual details', () => __awaiter(void 0, void 0, void 0, function* () {
        var _c;
        const UPDATE_QUERY = gql `
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
        const result = yield queryAsAdmin({
            query: UPDATE_QUERY,
            variables: { id: threatActorIndividualInternalId, input: UPDATES },
        });
        const threatActorIndividual = (_c = result.data) === null || _c === void 0 ? void 0 : _c.threatActorIndividualFieldPatch;
        expect(threatActorIndividual).not.toBeNull();
        expect(threatActorIndividual).toBeDefined();
        UPDATES.forEach(({ key, value }) => {
            expect(threatActorIndividual[key]).not.toBeNull();
            expect(threatActorIndividual[key]).toBeDefined();
            if (Array.isArray(value)) {
                expect(threatActorIndividual[key]).toHaveLength(value.length);
                expect(threatActorIndividual[key]).toStrictEqual(value);
            }
            else if (isDate(value)) {
                expect(threatActorIndividual[key].toISOString()).toEqual(value);
            }
            else {
                expect(threatActorIndividual[key]).toEqual(value);
            }
        });
    }));
    it('should update threat actor individual demographics', () => __awaiter(void 0, void 0, void 0, function* () {
        var _d, _e, _f;
        const UPDATE_QUERY = gql `
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
        const result = yield queryAsAdmin({
            query: UPDATE_QUERY,
            variables: { id: threatActorIndividualInternalId, input: UPDATES },
        });
        const threatActorIndividual = (_d = result.data) === null || _d === void 0 ? void 0 : _d.threatActorIndividualFieldPatch;
        expect(threatActorIndividual).not.toBeNull();
        expect(threatActorIndividual).toBeDefined();
        expect((_e = threatActorIndividual.bornIn) === null || _e === void 0 ? void 0 : _e.name).toEqual('France');
        expect((_f = threatActorIndividual.ethnicity) === null || _f === void 0 ? void 0 : _f.name).toEqual('France');
        expect(threatActorIndividual.date_of_birth.toISOString()).toEqual('1998-01-10T00:00:00.000Z');
        expect(threatActorIndividual.marital_status).toEqual('annulled');
        expect(threatActorIndividual.gender).toEqual('male');
        expect(threatActorIndividual.job_title).toEqual('A test hacker');
    }));
    it('should update threat actor individual core relationships', () => __awaiter(void 0, void 0, void 0, function* () {
        var _g, _h, _j, _k, _l;
        const getCoreRelationships = gql `
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
        const addCoreRelationship = gql `
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
        yield Promise.all(relationships.map((relationship_type) => queryAsAdmin({
            query: addCoreRelationship,
            variables: { input: {
                    fromId: threatActorIndividualInternalId,
                    toId: 'location--5acd8b26-51c2-4608-86ed-e9edd43ad971',
                    relationship_type,
                } }
        })));
        const { data } = yield queryAsAdmin({
            query: getCoreRelationships,
            variables: { id: threatActorIndividualInternalId },
        });
        expect((_h = (_g = data === null || data === void 0 ? void 0 : data.threatActorIndividual) === null || _g === void 0 ? void 0 : _g.stixCoreRelationships) === null || _h === void 0 ? void 0 : _h.edges).toHaveLength(3);
        const stixCoreRelationships = (_l = (_k = (_j = data === null || data === void 0 ? void 0 : data.threatActorIndividual) === null || _j === void 0 ? void 0 : _j.stixCoreRelationships) === null || _k === void 0 ? void 0 : _k.edges) === null || _l === void 0 ? void 0 : _l.map(({ node }) => (Object.assign({}, node)));
        expect(stixCoreRelationships).toHaveLength(3);
    }));
    it('should update threat actor individual biographics', () => __awaiter(void 0, void 0, void 0, function* () {
        var _m;
        const UPDATE_QUERY = gql `
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
        const result = yield queryAsAdmin({
            query: UPDATE_QUERY,
            variables: { id: threatActorIndividualInternalId, input: UPDATES },
        });
        const threatActorIndividual = (_m = result.data) === null || _m === void 0 ? void 0 : _m.threatActorIndividualFieldPatch;
        expect(threatActorIndividual).not.toBeNull();
        expect(threatActorIndividual).toBeDefined();
        expect(threatActorIndividual.eye_color).toEqual('hazel');
        expect(threatActorIndividual.hair_color).toEqual('brown');
    }));
    it('should update threat actor individual heights', () => __awaiter(void 0, void 0, void 0, function* () {
        var _o, _p, _q, _r;
        const HEIGHT_EDIT = gql `
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
        const REPLACE_ALL_HEIGHT = {
            key: 'height',
            object_path: '/height/0',
            value: [{ measure: 182, date_seen: DATES[0] }],
            operation: EditOperation.Replace,
        };
        const ADD_HEIGHTS = {
            key: 'height',
            value: [
                { measure: 189, date_seen: DATES[1] },
                { measure: 190, date_seen: DATES[2] },
            ],
            operation: EditOperation.Add,
        };
        const REPLACE_INDEX_HEIGHT = {
            key: 'height',
            object_path: '/height/0',
            value: [{ measure: 183, date_seen: DATES[0] }],
            operation: EditOperation.Replace,
        };
        const REMOVE_INDEX_HEIGHT = {
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
        const replaceAll = yield queryAsAdmin({
            query: HEIGHT_EDIT,
            variables: { id: threatActorIndividualInternalId, input: [REPLACE_ALL_HEIGHT] },
        });
        let threatActorIndividual = (_o = replaceAll === null || replaceAll === void 0 ? void 0 : replaceAll.data) === null || _o === void 0 ? void 0 : _o.threatActorIndividualFieldPatch;
        expect(threatActorIndividual).not.toBeNull();
        expect(threatActorIndividual).toBeDefined();
        expect(threatActorIndividual.height).toHaveLength(1);
        expect(threatActorIndividual.height[0]).toEqual(expectedHeights[0]);
        const addHeights = yield queryAsAdmin({
            query: HEIGHT_EDIT,
            variables: { id: threatActorIndividualInternalId, input: [ADD_HEIGHTS] },
        });
        threatActorIndividual = (_p = addHeights === null || addHeights === void 0 ? void 0 : addHeights.data) === null || _p === void 0 ? void 0 : _p.threatActorIndividualFieldPatch;
        expect(threatActorIndividual).not.toBeNull();
        expect(threatActorIndividual).toBeDefined();
        expect(threatActorIndividual === null || threatActorIndividual === void 0 ? void 0 : threatActorIndividual.height).toHaveLength(3);
        expect(threatActorIndividual.height[0]).toEqual(expectedHeights[0]); // 182
        expect(threatActorIndividual.height[1]).toEqual(expectedHeights[2]); // 189
        expect(threatActorIndividual.height[2]).toEqual(expectedHeights[3]); // 190
        const replaceIndex = yield queryAsAdmin({
            query: HEIGHT_EDIT,
            variables: { id: threatActorIndividualInternalId, input: [REPLACE_INDEX_HEIGHT] },
        });
        threatActorIndividual = (_q = replaceIndex === null || replaceIndex === void 0 ? void 0 : replaceIndex.data) === null || _q === void 0 ? void 0 : _q.threatActorIndividualFieldPatch;
        expect(threatActorIndividual).not.toBeNull();
        expect(threatActorIndividual).toBeDefined();
        expect(threatActorIndividual.height).toHaveLength(3);
        expect(threatActorIndividual.height[0]).toEqual(expectedHeights[1]); // 183
        expect(threatActorIndividual.height[1]).toEqual(expectedHeights[2]); // 189
        expect(threatActorIndividual.height[2]).toEqual(expectedHeights[3]); // 190
        const removeIndex = yield queryAsAdmin({
            query: HEIGHT_EDIT,
            variables: { id: threatActorIndividualInternalId, input: [REMOVE_INDEX_HEIGHT] },
        });
        threatActorIndividual = (_r = removeIndex === null || removeIndex === void 0 ? void 0 : removeIndex.data) === null || _r === void 0 ? void 0 : _r.threatActorIndividualFieldPatch;
        expect(threatActorIndividual).not.toBeNull();
        expect(threatActorIndividual).toBeDefined();
        expect(threatActorIndividual.height).toHaveLength(2);
        expect(threatActorIndividual.height[0]).toEqual(expectedHeights[1]); // 183
        expect(threatActorIndividual.height[1]).toEqual(expectedHeights[2]); // 189
    }));
    it('should update partial height', () => __awaiter(void 0, void 0, void 0, function* () {
        var _s;
        const HEIGHT_EDIT = gql `
          mutation threatActorIndividualHeightEdit($id: ID!, $input: [EditInput]!) {
            threatActorIndividualFieldPatch(id:$id, input:$input) {
              height {
                measure
                date_seen
              }
            }
          }
        `;
        const REPLACE_MEASURE_ONLY = {
            key: 'height',
            object_path: '/height/0/measure',
            value: [283],
            operation: EditOperation.Replace,
        };
        const replaceMeasure = yield queryAsAdmin({
            query: HEIGHT_EDIT,
            variables: { id: threatActorIndividualInternalId, input: [REPLACE_MEASURE_ONLY] },
        });
        const threatActorIndividual = (_s = replaceMeasure === null || replaceMeasure === void 0 ? void 0 : replaceMeasure.data) === null || _s === void 0 ? void 0 : _s.threatActorIndividualFieldPatch;
        expect(threatActorIndividual).not.toBeNull();
        expect(threatActorIndividual).toBeDefined();
        expect(threatActorIndividual.height).toHaveLength(2);
        expect(threatActorIndividual.height[0].measure).toBe(283);
    }));
    it('should remove all height', () => __awaiter(void 0, void 0, void 0, function* () {
        var _t;
        const HEIGHT_EDIT = gql `
      mutation threatActorIndividualHeightEdit($id: ID!, $input: [EditInput]!) {
        threatActorIndividualFieldPatch(id:$id, input:$input) {
          height {
            measure
            date_seen
          }
        }
      }
    `;
        const REMOVE_ALL_HEIGHTS = {
            key: 'height',
            value: [],
            object_path: '/height',
            operation: EditOperation.Remove,
        };
        const removeAll = yield queryAsAdmin({
            query: HEIGHT_EDIT,
            variables: { id: threatActorIndividualInternalId, input: [REMOVE_ALL_HEIGHTS] },
        });
        const threatActorIndividual = (_t = removeAll === null || removeAll === void 0 ? void 0 : removeAll.data) === null || _t === void 0 ? void 0 : _t.threatActorIndividualFieldPatch;
        expect(threatActorIndividual).not.toBeNull();
        expect(threatActorIndividual).toBeDefined();
        expect(threatActorIndividual.height).toHaveLength(0);
    }));
    it('should update threat actor individual weight', () => __awaiter(void 0, void 0, void 0, function* () {
        var _u, _v, _w, _x, _y;
        const WEIGHT_EDIT = gql `
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
        const REPLACE_ALL_WEIGHT = {
            key: 'weight',
            value: [{ measure: 182, date_seen: DATES[0] }],
            operation: EditOperation.Replace,
        };
        const ADD_WEIGHTS = {
            key: 'weight',
            value: [
                { measure: 190, date_seen: DATES[2] },
                { measure: 189, date_seen: DATES[1] },
            ],
            operation: EditOperation.Add,
        };
        const REPLACE_INDEX_WEIGHT = {
            key: 'weight',
            object_path: '/weight/0',
            value: [{ measure: 183, date_seen: DATES[0] }],
            operation: EditOperation.Replace,
        };
        const REMOVE_INDEX_WEIGHT = {
            key: 'weight',
            value: [],
            object_path: '/weight/2',
            operation: EditOperation.Remove,
        };
        const REMOVE_ALL_WEIGHTS = {
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
        const replaceAll = yield queryAsAdmin({
            query: WEIGHT_EDIT,
            variables: { id: threatActorIndividualInternalId, input: [REPLACE_ALL_WEIGHT] },
        });
        let threatActorIndividual = (_u = replaceAll === null || replaceAll === void 0 ? void 0 : replaceAll.data) === null || _u === void 0 ? void 0 : _u.threatActorIndividualFieldPatch;
        expect(threatActorIndividual).not.toBeNull();
        expect(threatActorIndividual).toBeDefined();
        expect(threatActorIndividual.weight).toHaveLength(1);
        expect(threatActorIndividual.weight[0]).toEqual(expectedWeights[0]);
        const addHeights = yield queryAsAdmin({
            query: WEIGHT_EDIT,
            variables: { id: threatActorIndividualInternalId, input: [ADD_WEIGHTS] },
        });
        threatActorIndividual = (_v = addHeights === null || addHeights === void 0 ? void 0 : addHeights.data) === null || _v === void 0 ? void 0 : _v.threatActorIndividualFieldPatch;
        expect(threatActorIndividual).not.toBeNull();
        expect(threatActorIndividual).toBeDefined();
        expect(threatActorIndividual === null || threatActorIndividual === void 0 ? void 0 : threatActorIndividual.weight).toHaveLength(3);
        expect(threatActorIndividual.weight[0]).toEqual(expectedWeights[0]);
        expect(threatActorIndividual.weight[1]).toEqual(expectedWeights[2]);
        expect(threatActorIndividual.weight[2]).toEqual(expectedWeights[3]);
        const replaceIndex = yield queryAsAdmin({
            query: WEIGHT_EDIT,
            variables: { id: threatActorIndividualInternalId, input: [REPLACE_INDEX_WEIGHT] },
        });
        threatActorIndividual = (_w = replaceIndex === null || replaceIndex === void 0 ? void 0 : replaceIndex.data) === null || _w === void 0 ? void 0 : _w.threatActorIndividualFieldPatch;
        expect(threatActorIndividual).not.toBeNull();
        expect(threatActorIndividual).toBeDefined();
        expect(threatActorIndividual.weight).toHaveLength(3);
        expect(threatActorIndividual.weight[0]).toEqual(expectedWeights[1]);
        expect(threatActorIndividual.weight[1]).toEqual(expectedWeights[2]);
        expect(threatActorIndividual.weight[2]).toEqual(expectedWeights[3]);
        const removeIndex = yield queryAsAdmin({
            query: WEIGHT_EDIT,
            variables: { id: threatActorIndividualInternalId, input: [REMOVE_INDEX_WEIGHT] },
        });
        threatActorIndividual = (_x = removeIndex === null || removeIndex === void 0 ? void 0 : removeIndex.data) === null || _x === void 0 ? void 0 : _x.threatActorIndividualFieldPatch;
        expect(threatActorIndividual).not.toBeNull();
        expect(threatActorIndividual).toBeDefined();
        expect(threatActorIndividual.weight).toHaveLength(2);
        expect(threatActorIndividual.weight[0]).toEqual(expectedWeights[1]);
        expect(threatActorIndividual.weight[1]).toEqual(expectedWeights[3]);
        const removeAll = yield queryAsAdmin({
            query: WEIGHT_EDIT,
            variables: { id: threatActorIndividualInternalId, input: [REMOVE_ALL_WEIGHTS] },
        });
        threatActorIndividual = (_y = removeAll === null || removeAll === void 0 ? void 0 : removeAll.data) === null || _y === void 0 ? void 0 : _y.threatActorIndividualFieldPatch;
        expect(threatActorIndividual).not.toBeNull();
        expect(threatActorIndividual).toBeDefined();
        expect(threatActorIndividual.weight).toHaveLength(0);
    }));
    it.skip('should fail update for invalid input', () => __awaiter(void 0, void 0, void 0, function* () {
        var _z, _0;
        const WEIGHT_EDIT = gql `
      mutation threatActorIndividualWeightEdit($id: ID!, $input: [EditInput]!) {
        threatActorIndividualFieldPatch(id:$id, input:$input) {
          weight {
            measure
            date_seen
          }
        }
      }
    `;
        const ADD_WEIGHTS = {
            key: 'weight',
            value: [
                { measure: 190, date_seen: '2017-11-06T00:00:00.000Z' },
                { measure: 189, date_seen_invalid: '2017-11-06T00:00:00.000Z' },
            ],
            operation: EditOperation.Add,
        };
        const addHeights = yield queryAsAdmin({
            query: WEIGHT_EDIT,
            variables: { id: threatActorIndividualInternalId, input: [ADD_WEIGHTS] },
        });
        expect((_z = addHeights === null || addHeights === void 0 ? void 0 : addHeights.data) === null || _z === void 0 ? void 0 : _z.threatActorIndividualFieldPatch).toBeNull();
        expect((_0 = addHeights === null || addHeights === void 0 ? void 0 : addHeights.errors) === null || _0 === void 0 ? void 0 : _0.length).toBe(1);
    }));
    it('should delete threat actor individual', () => __awaiter(void 0, void 0, void 0, function* () {
        var _1;
        const DELETE_QUERY = gql `
      mutation threatActorIndividualDelete($id: ID!) {
        threatActorIndividualDelete(id: $id)
      }
    `;
        yield queryAsAdmin({
            query: DELETE_QUERY,
            variables: { id: threatActorIndividualInternalId },
        });
        const queryResult = yield queryAsAdmin({
            query: READ_QUERY,
            variables: { id: threatActorIndividualInternalId },
        });
        expect(queryResult).not.toBeNull();
        expect((_1 = queryResult.data) === null || _1 === void 0 ? void 0 : _1.threatActorIndividual).toBeNull();
    }));
});
