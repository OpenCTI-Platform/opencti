var __awaiter = (this && this.__awaiter) || function (thisArg, _arguments, P, generator) {
    function adopt(value) { return value instanceof P ? value : new P(function (resolve) { resolve(value); }); }
    return new (P || (P = Promise))(function (resolve, reject) {
        function fulfilled(value) { try { step(generator.next(value)); } catch (e) { reject(e); } }
        function rejected(value) { try { step(generator["throw"](value)); } catch (e) { reject(e); } }
        function step(result) { result.done ? resolve(result.value) : adopt(result.value).then(fulfilled, rejected); }
        step((generator = generator.apply(thisArg, _arguments || [])).next());
    });
};
import { expect, it, describe } from 'vitest';
import gql from 'graphql-tag';
import { queryAsAdmin } from '../../utils/testQuery';
// import type { Indicator } from '../../../src/generated/graphql';
const LIST_QUERY = gql `
    query indicators(
        $first: Int
        $after: ID
        $orderBy: IndicatorsOrdering
        $orderMode: OrderingMode
        $filters: FilterGroup
        $search: String
    ) {
        indicators(
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
                    standard_id
                    name
                    description
                }
            }
        }
    }
`;
const READ_QUERY = gql `
    query indicator($id: String!) {
        indicator(id: $id) {
            id
            standard_id
            name
            description
            toStix
        }
    }
`;
describe('Indicator resolver standard behavior', () => {
    let indicatorInternalId;
    const indicatorStixId = 'indicator--f6ad652c-166a-43e6-98b8-8ff078e2349f';
    it('should indicator created', () => __awaiter(void 0, void 0, void 0, function* () {
        var _a, _b, _c, _d;
        const CREATE_QUERY = gql `
        mutation IndicatorAdd($input: IndicatorAddInput!) {
            indicatorAdd(input: $input) {
                id
                name
                description
                observables {
                    edges {
                        node {
                            id
                            standard_id
                        }
                    }
                }
            }
        }
    `;
        // Create the indicator
        const INDICATOR_TO_CREATE = {
            input: {
                name: 'Indicator',
                stix_id: indicatorStixId,
                description: 'Indicator description',
                pattern: "[domain-name:value = 'www.payah.rest']",
                pattern_type: 'stix',
                x_opencti_main_observable_type: 'Domain-Name',
            },
        };
        const indicator = yield queryAsAdmin({
            query: CREATE_QUERY,
            variables: INDICATOR_TO_CREATE,
        });
        expect(indicator).not.toBeNull();
        expect((_a = indicator.data) === null || _a === void 0 ? void 0 : _a.indicatorAdd).not.toBeNull();
        expect((_b = indicator.data) === null || _b === void 0 ? void 0 : _b.indicatorAdd.name).toEqual('Indicator');
        expect((_c = indicator.data) === null || _c === void 0 ? void 0 : _c.indicatorAdd.observables.edges.length).toEqual(0);
        indicatorInternalId = (_d = indicator.data) === null || _d === void 0 ? void 0 : _d.indicatorAdd.id;
    }));
    it('should indicator loaded by internal id', () => __awaiter(void 0, void 0, void 0, function* () {
        var _e, _f, _g;
        const queryResult = yield queryAsAdmin({ query: READ_QUERY, variables: { id: indicatorInternalId } });
        expect(queryResult).not.toBeNull();
        expect((_e = queryResult.data) === null || _e === void 0 ? void 0 : _e.indicator).not.toBeNull();
        expect((_f = queryResult.data) === null || _f === void 0 ? void 0 : _f.indicator.id).toEqual(indicatorInternalId);
        expect((_g = queryResult.data) === null || _g === void 0 ? void 0 : _g.indicator.toStix.length).toBeGreaterThan(5);
    }));
    it('should indicator loaded by stix id', () => __awaiter(void 0, void 0, void 0, function* () {
        var _h, _j;
        const queryResult = yield queryAsAdmin({ query: READ_QUERY, variables: { id: indicatorStixId } });
        expect(queryResult).not.toBeNull();
        expect((_h = queryResult.data) === null || _h === void 0 ? void 0 : _h.indicator).not.toBeNull();
        expect((_j = queryResult.data) === null || _j === void 0 ? void 0 : _j.indicator.id).toEqual(indicatorInternalId);
    }));
    it('should list indicators', () => __awaiter(void 0, void 0, void 0, function* () {
        var _k;
        const queryResult = yield queryAsAdmin({ query: LIST_QUERY, variables: { first: 10 } });
        expect((_k = queryResult.data) === null || _k === void 0 ? void 0 : _k.indicators.edges.length).toEqual(4);
    }));
    it('should update indicator', () => __awaiter(void 0, void 0, void 0, function* () {
        var _l;
        const UPDATE_QUERY = gql `
        mutation IndicatorFieldPatch($id: ID!, $input: [EditInput]!) {
            indicatorFieldPatch(id: $id, input: $input) {
                id
                name
            }
        }
    `;
        const queryResult = yield queryAsAdmin({
            query: UPDATE_QUERY,
            variables: { id: indicatorInternalId, input: { key: 'name', value: ['Indicator - test'] } },
        });
        expect((_l = queryResult.data) === null || _l === void 0 ? void 0 : _l.indicatorFieldPatch.name).toEqual('Indicator - test');
    }));
    it('should context patch indicator', () => __awaiter(void 0, void 0, void 0, function* () {
        var _m;
        const CONTEXT_PATCH_QUERY = gql `
        mutation IndicatorContextPatch($id: ID!, $input: EditContext) {
            indicatorContextPatch(id: $id, input: $input) {
              id
            }
        }
    `;
        const queryResult = yield queryAsAdmin({
            query: CONTEXT_PATCH_QUERY,
            variables: { id: indicatorInternalId, input: { focusOn: 'description' } },
        });
        expect((_m = queryResult.data) === null || _m === void 0 ? void 0 : _m.indicatorContextPatch.id).toEqual(indicatorInternalId);
    }));
    it('should context clean indicator', () => __awaiter(void 0, void 0, void 0, function* () {
        var _o;
        const CONTEXT_PATCH_QUERY = gql `
        mutation IndicatorContextClean($id: ID!) {
            indicatorContextClean(id: $id) {
              id
            }
        }
    `;
        const queryResult = yield queryAsAdmin({
            query: CONTEXT_PATCH_QUERY,
            variables: { id: indicatorInternalId },
        });
        expect((_o = queryResult.data) === null || _o === void 0 ? void 0 : _o.indicatorContextClean.id).toEqual(indicatorInternalId);
    }));
    it('should add relation in indicator', () => __awaiter(void 0, void 0, void 0, function* () {
        var _p;
        const RELATION_ADD_QUERY = gql `
        mutation IndicatorRelationAdd($id: ID!, $input: StixRefRelationshipAddInput!) {
            indicatorRelationAdd(id: $id, input: $input) {
                id
                from {
                    ... on Indicator {
                        objectMarking {
                            id
                        }
                    }
                }
            }
        }
    `;
        const queryResult = yield queryAsAdmin({
            query: RELATION_ADD_QUERY,
            variables: {
                id: indicatorInternalId,
                input: {
                    toId: 'marking-definition--78ca4366-f5b8-4764-83f7-34ce38198e27',
                    relationship_type: 'object-marking',
                },
            },
        });
        expect((_p = queryResult.data) === null || _p === void 0 ? void 0 : _p.indicatorRelationAdd.from.objectMarking.length).toEqual(1);
    }));
    it('should delete relation in indicator', () => __awaiter(void 0, void 0, void 0, function* () {
        var _q;
        const RELATION_DELETE_QUERY = gql `
        mutation IndicatorRelationDelete($id: ID!, $toId: StixRef!, $relationship_type: String!) {
            indicatorRelationDelete(id: $id, toId: $toId, relationship_type: $relationship_type) {
                id
                objectMarking {
                    id
                }
            }
        }
    `;
        const queryResult = yield queryAsAdmin({
            query: RELATION_DELETE_QUERY,
            variables: {
                id: indicatorInternalId,
                toId: 'marking-definition--78ca4366-f5b8-4764-83f7-34ce38198e27',
                relationship_type: 'object-marking',
            },
        });
        expect((_q = queryResult.data) === null || _q === void 0 ? void 0 : _q.indicatorRelationDelete.objectMarking.length).toEqual(0);
    }));
    it('should indicator deleted', () => __awaiter(void 0, void 0, void 0, function* () {
        var _r;
        const DELETE_QUERY = gql `
        mutation indicatorDelete($id: ID!) {
            indicatorDelete(id: $id)
        }
    `;
        // Delete the indicator
        yield queryAsAdmin({
            query: DELETE_QUERY,
            variables: { id: indicatorInternalId },
        });
        // Verify is no longer found
        const queryResult = yield queryAsAdmin({ query: READ_QUERY, variables: { id: indicatorStixId } });
        expect(queryResult).not.toBeNull();
        expect((_r = queryResult.data) === null || _r === void 0 ? void 0 : _r.indicator).toBeNull();
    }));
});
