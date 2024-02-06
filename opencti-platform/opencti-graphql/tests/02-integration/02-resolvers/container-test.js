var __awaiter = (this && this.__awaiter) || function (thisArg, _arguments, P, generator) {
    function adopt(value) { return value instanceof P ? value : new P(function (resolve) { resolve(value); }); }
    return new (P || (P = Promise))(function (resolve, reject) {
        function fulfilled(value) { try { step(generator.next(value)); } catch (e) { reject(e); } }
        function rejected(value) { try { step(generator["throw"](value)); } catch (e) { reject(e); } }
        function step(result) { result.done ? resolve(result.value) : adopt(result.value).then(fulfilled, rejected); }
        step((generator = generator.apply(thisArg, _arguments || [])).next());
    });
};
import { describe, expect, it } from 'vitest';
import * as R from 'ramda';
import gql from 'graphql-tag';
import { queryAsAdmin } from '../../utils/testQuery';
import { isStixCoreObject } from '../../../src/schema/stixCoreObject';
import { isStixCoreRelationship } from '../../../src/schema/stixCoreRelationship';
import { isStixRefRelationship } from '../../../src/schema/stixRefRelationship';
describe('Container resolver standard behavior', () => {
    const REPORT_RAW_ID = 'report--a445d22a-db0c-4b5d-9ec8-e9ad0b6dbdd7';
    const REPORT_ID = 'report--f3e554eb-60f5-587c-9191-4f25e9ba9f32';
    it('should container loaded by internal id', () => __awaiter(void 0, void 0, void 0, function* () {
        var _a, _b;
        const queryResult = yield queryAsAdmin({
            query: gql `
          query container($id: String!) {
            container(id: $id) {
              id
              standard_id
            }
          }
        `,
            variables: { id: REPORT_RAW_ID }
        });
        expect(queryResult).not.toBeNull();
        expect((_a = queryResult.data) === null || _a === void 0 ? void 0 : _a.container).not.toBeNull();
        expect((_b = queryResult.data) === null || _b === void 0 ? void 0 : _b.container.standard_id).toEqual(REPORT_ID);
    }));
    it('should containers list loaded', () => __awaiter(void 0, void 0, void 0, function* () {
        var _c, _d, _e;
        const queryResult = yield queryAsAdmin({
            query: gql `
            query containers {
              containers(first: 1, orderBy: created, orderMode: asc) {
                edges {
                  node {
                    standard_id
                    entity_type
                  }
                }
              }
            }
          `,
        });
        expect(queryResult).not.toBeNull();
        expect((_c = queryResult.data) === null || _c === void 0 ? void 0 : _c.containers).not.toBeNull();
        expect((_d = queryResult.data) === null || _d === void 0 ? void 0 : _d.containers.edges.length).toEqual(1);
        expect((_e = queryResult.data) === null || _e === void 0 ? void 0 : _e.containers.edges[0].node.standard_id).toEqual('observed-data--d5c0414a-aeb6-5927-a2ae-e465846c206f');
    }));
    it('should malware containersNumber accurate', () => __awaiter(void 0, void 0, void 0, function* () {
        var _f, _g, _h, _j;
        const queryResult = yield queryAsAdmin({
            query: gql `
            query malware {
              attackPattern(id: "attack-pattern--2fc04aa5-48c1-49ec-919a-b88241ef1d17") {
                standard_id
                containersNumber {
                  count
                  total
                }
              }
            }
          `,
        });
        expect(queryResult).not.toBeNull();
        expect((_f = queryResult.data) === null || _f === void 0 ? void 0 : _f.attackPattern).not.toBeNull();
        expect((_g = queryResult.data) === null || _g === void 0 ? void 0 : _g.attackPattern.standard_id).toEqual('attack-pattern--a01046cc-192f-5d52-8e75-6e447fae3890');
        expect((_h = queryResult.data) === null || _h === void 0 ? void 0 : _h.attackPattern.containersNumber.count).toEqual(1);
        expect((_j = queryResult.data) === null || _j === void 0 ? void 0 : _j.attackPattern.containersNumber.total).toEqual(1);
    }));
    it('should container objects loaded', () => __awaiter(void 0, void 0, void 0, function* () {
        var _k, _l, _m, _o, _p;
        const queryResult = yield queryAsAdmin({
            query: gql `
            query container($id: String!) {
              container(id: $id) {
                id
                standard_id
                relatedContainers {
                  edges {
                     node {
                       standard_id
                     }
                  }
                }
                numberOfConnectedElement
                objects(first: 1, orderBy: created, orderMode: asc) {
                  edges {
                    node {
                      __typename
                      ... on StixCoreRelationship {
                        id
                        standard_id
                      }
                      ... on StixCoreObject {
                        id
                        standard_id
                      }
                    }
                  }
                }
              }
            }
          `,
            variables: { id: REPORT_RAW_ID }
        });
        expect(queryResult).not.toBeNull();
        expect((_k = queryResult.data) === null || _k === void 0 ? void 0 : _k.container).not.toBeNull();
        expect((_l = queryResult.data) === null || _l === void 0 ? void 0 : _l.container.standard_id).toEqual(REPORT_ID);
        expect((_m = queryResult.data) === null || _m === void 0 ? void 0 : _m.container.numberOfConnectedElement).toEqual(29);
        expect((_o = queryResult.data) === null || _o === void 0 ? void 0 : _o.container.relatedContainers.edges.length).toEqual(4);
        expect((_p = queryResult.data) === null || _p === void 0 ? void 0 : _p.container.objects.edges.length).toEqual(1);
    }));
    it('should container frst 1 object', () => __awaiter(void 0, void 0, void 0, function* () {
        var _q, _r, _s;
        const queryResult = yield queryAsAdmin({
            query: gql `
            query container($id: String!) {
              container(id: $id) {
                id
                standard_id
                objects(first: 1, orderBy: created, orderMode: asc) {
                  edges {
                    node {
                      __typename
                      ... on StixCoreRelationship {
                        id
                        standard_id
                      }
                      ... on StixCoreObject {
                        id
                        standard_id
                      }
                    }
                  }
                }
              }
            }
          `,
            variables: { id: REPORT_RAW_ID }
        });
        expect(queryResult).not.toBeNull();
        expect((_q = queryResult.data) === null || _q === void 0 ? void 0 : _q.container).not.toBeNull();
        expect((_r = queryResult.data) === null || _r === void 0 ? void 0 : _r.container.standard_id).toEqual(REPORT_ID);
        expect((_s = queryResult.data) === null || _s === void 0 ? void 0 : _s.container.objects.edges.length).toEqual(1);
    }));
    it('should container all objects', () => __awaiter(void 0, void 0, void 0, function* () {
        var _t, _u, _v, _w, _x;
        const queryResult = yield queryAsAdmin({
            query: gql `
            query container($id: String!) {
              container(id: $id) {
                id
                standard_id
                objects(all: true, first: 10, orderBy: created, orderMode: asc) {
                  edges {
                    node {
                      ... on StixCoreRelationship {
                        id
                        entity_type
                        standard_id
                      }
                      ... on StixCoreObject {
                        id
                        entity_type
                        standard_id
                      }
                    }
                  }
                }
              }
            }
          `,
            variables: { id: REPORT_RAW_ID }
        });
        expect(queryResult).not.toBeNull();
        expect((_t = queryResult.data) === null || _t === void 0 ? void 0 : _t.container).not.toBeNull();
        expect((_u = queryResult.data) === null || _u === void 0 ? void 0 : _u.container.standard_id).toEqual(REPORT_ID);
        expect((_v = queryResult.data) === null || _v === void 0 ? void 0 : _v.container.objects.edges.length).toEqual(26);
        const entities = (_w = queryResult.data) === null || _w === void 0 ? void 0 : _w.container.objects.edges.filter((e) => isStixCoreObject(e.node.entity_type));
        expect(entities.length).toEqual(15);
        const relationships = (_x = queryResult.data) === null || _x === void 0 ? void 0 : _x.container.objects.edges.filter((e) => isStixCoreRelationship(e.node.entity_type));
        expect(relationships.length).toEqual(11);
    }));
    it('should container containersObjectsOfObject from malware', () => __awaiter(void 0, void 0, void 0, function* () {
        var _y, _z, _0, _1;
        const queryResult = yield queryAsAdmin({
            query: gql `
            query container($id: String!) {
              containersObjectsOfObject(id: $id, types: "Malware") {
                edges {
                  node {
                    __typename
                    ... on StixCoreObject {
                      entity_type
                    }
                    ... on StixRefRelationship {
                      entity_type
                      to {
                        ... on StixCoreObject {
                          standard_id
                          entity_type
                        }
                      }
                    }
                  }
                }                
              }
            }
          `,
            variables: { id: 'malware--faa5b705-cf44-4e50-8472-29e5fec43c3c' }
        });
        expect(queryResult).not.toBeNull();
        expect((_y = queryResult.data) === null || _y === void 0 ? void 0 : _y.containersObjectsOfObject).not.toBeNull();
        expect((_z = queryResult.data) === null || _z === void 0 ? void 0 : _z.containersObjectsOfObject.edges.length).toEqual(9);
        const entities = (_0 = queryResult.data) === null || _0 === void 0 ? void 0 : _0.containersObjectsOfObject.edges.filter((e) => isStixCoreObject(e.node.entity_type));
        expect(entities.length).toEqual(5);
        const relationships = (_1 = queryResult.data) === null || _1 === void 0 ? void 0 : _1.containersObjectsOfObject.edges.filter((e) => isStixRefRelationship(e.node.entity_type));
        expect(relationships.length).toEqual(4);
        expect(R.uniq(relationships.map((r) => r.node.to.standard_id))).toEqual(['malware--21c45dbe-54ec-5bb7-b8cd-9f27cc518714']);
    }));
});
