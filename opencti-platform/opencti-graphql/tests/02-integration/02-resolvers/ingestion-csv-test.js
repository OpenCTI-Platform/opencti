var __awaiter = (this && this.__awaiter) || function (thisArg, _arguments, P, generator) {
    function adopt(value) { return value instanceof P ? value : new P(function (resolve) { resolve(value); }); }
    return new (P || (P = Promise))(function (resolve, reject) {
        function fulfilled(value) { try { step(generator.next(value)); } catch (e) { reject(e); } }
        function rejected(value) { try { step(generator["throw"](value)); } catch (e) { reject(e); } }
        function step(result) { result.done ? resolve(result.value) : adopt(result.value).then(fulfilled, rejected); }
        step((generator = generator.apply(thisArg, _arguments || [])).next());
    });
};
import { describe, it, expect, beforeAll } from 'vitest';
import gql from 'graphql-tag';
import { ADMIN_USER, queryAsAdmin } from '../../utils/testQuery';
describe('CSV ingestion resolver standard behavior', () => {
    let singleColumnCsvMapperId = '';
    let singleColumnCsvFeedIngesterId = '';
    beforeAll(() => __awaiter(void 0, void 0, void 0, function* () {
        var _a, _b;
        const SINGLE_COLUMN_CSV_MAPPER = {
            input: {
                has_header: false,
                name: 'Single column CSV mapper',
                separator: ',',
                representations: '[{"id":"75c3c21c-0a92-497f-962d-4e6e1a488481","type":"entity","target":{"entity_type":"IPv4-Addr"},"attributes":[{"key":"value","column":{"column_name":"A"},"based_on":null}]}]',
                skipLineChar: ''
            }
        };
        const createSingleColumnCsvMapperQueryResult = yield queryAsAdmin({
            query: gql `
      mutation createSingleColumnCsvMapper($input: CsvMapperAddInput!) {
        csvMapperAdd(input: $input) {
          id
        }
      },
      `,
            variables: SINGLE_COLUMN_CSV_MAPPER
        });
        singleColumnCsvMapperId = (_b = (_a = createSingleColumnCsvMapperQueryResult === null || createSingleColumnCsvMapperQueryResult === void 0 ? void 0 : createSingleColumnCsvMapperQueryResult.data) === null || _a === void 0 ? void 0 : _a.csvMapperAdd) === null || _b === void 0 ? void 0 : _b.id;
    }));
    it('should create a CSV feeds ingester', () => __awaiter(void 0, void 0, void 0, function* () {
        var _c, _d, _e, _f, _g, _h;
        const CSV_FEED_INGESTER_TO_CREATE = {
            input: {
                authentication_type: 'none',
                name: 'Single column',
                uri: 'https://lists.blocklist.de/lists/all.txt',
                csv_mapper_id: singleColumnCsvMapperId,
                user_id: ADMIN_USER.id
            }
        };
        const createSingleColumnCsvFeedsIngesterQueryResult = yield queryAsAdmin({
            query: gql `
      mutation createSingleColumnCsvFeedsIngester($input: IngestionCsvAddInput!) {
        ingestionCsvAdd(input: $input) {
        id
        entity_type
        ingestion_running
          }
      },
      `,
            variables: CSV_FEED_INGESTER_TO_CREATE
        });
        singleColumnCsvFeedIngesterId = (_d = (_c = createSingleColumnCsvFeedsIngesterQueryResult === null || createSingleColumnCsvFeedsIngesterQueryResult === void 0 ? void 0 : createSingleColumnCsvFeedsIngesterQueryResult.data) === null || _c === void 0 ? void 0 : _c.ingestionCsvAdd) === null || _d === void 0 ? void 0 : _d.id;
        expect(singleColumnCsvFeedIngesterId).toBeDefined();
        expect((_f = (_e = createSingleColumnCsvFeedsIngesterQueryResult === null || createSingleColumnCsvFeedsIngesterQueryResult === void 0 ? void 0 : createSingleColumnCsvFeedsIngesterQueryResult.data) === null || _e === void 0 ? void 0 : _e.ingestionCsvAdd) === null || _f === void 0 ? void 0 : _f.entity_type).toBe('IngestionCsv');
        expect((_h = (_g = createSingleColumnCsvFeedsIngesterQueryResult === null || createSingleColumnCsvFeedsIngesterQueryResult === void 0 ? void 0 : createSingleColumnCsvFeedsIngesterQueryResult.data) === null || _g === void 0 ? void 0 : _g.ingestionCsvAdd) === null || _h === void 0 ? void 0 : _h.ingestion_running).toBeFalsy();
    }));
    it('should create a CSV feeds ingester with authentication', () => __awaiter(void 0, void 0, void 0, function* () {
        var _j, _k, _l, _m, _o, _p;
        const CSV_FEED_INGESTER_TO_CREATE = {
            input: {
                authentication_type: 'none',
                name: 'Single column',
                uri: 'https://lists.blocklist.de/lists/all.txt',
                csv_mapper_id: singleColumnCsvMapperId,
                user_id: ADMIN_USER.id
            }
        };
        const createSingleColumnCsvFeedsIngesterQueryResult = yield queryAsAdmin({
            query: gql `
          mutation createSingleColumnCsvFeedsIngester($input: IngestionCsvAddInput!) {
              ingestionCsvAdd(input: $input) {
                  id
                  entity_type
                  ingestion_running
              }
          },
      `,
            variables: CSV_FEED_INGESTER_TO_CREATE
        });
        singleColumnCsvFeedIngesterId = (_k = (_j = createSingleColumnCsvFeedsIngesterQueryResult === null || createSingleColumnCsvFeedsIngesterQueryResult === void 0 ? void 0 : createSingleColumnCsvFeedsIngesterQueryResult.data) === null || _j === void 0 ? void 0 : _j.ingestionCsvAdd) === null || _k === void 0 ? void 0 : _k.id;
        expect(singleColumnCsvFeedIngesterId).toBeDefined();
        expect((_m = (_l = createSingleColumnCsvFeedsIngesterQueryResult === null || createSingleColumnCsvFeedsIngesterQueryResult === void 0 ? void 0 : createSingleColumnCsvFeedsIngesterQueryResult.data) === null || _l === void 0 ? void 0 : _l.ingestionCsvAdd) === null || _m === void 0 ? void 0 : _m.entity_type).toBe('IngestionCsv');
        expect((_p = (_o = createSingleColumnCsvFeedsIngesterQueryResult === null || createSingleColumnCsvFeedsIngesterQueryResult === void 0 ? void 0 : createSingleColumnCsvFeedsIngesterQueryResult.data) === null || _o === void 0 ? void 0 : _o.ingestionCsvAdd) === null || _p === void 0 ? void 0 : _p.ingestion_running).toBeFalsy();
    }));
    it('should start the CSV feeds ingester', () => __awaiter(void 0, void 0, void 0, function* () {
        var _q, _r;
        const CSV_FEED_INGESTER_TO_START = {
            id: singleColumnCsvFeedIngesterId,
            input: {
                key: 'ingestion_running',
                value: [true],
            }
        };
        const startSingleColumnCsvFeedsIngesterQueryResult = yield queryAsAdmin({
            query: gql `
      mutation startSingleColumnCsvFeedsIngester($id: ID!, $input: [EditInput!]!) {
        ingestionCsvFieldPatch(id: $id, input: $input){
          ingestion_running
        }
      }
      `,
            variables: CSV_FEED_INGESTER_TO_START
        });
        expect((_r = (_q = startSingleColumnCsvFeedsIngesterQueryResult === null || startSingleColumnCsvFeedsIngesterQueryResult === void 0 ? void 0 : startSingleColumnCsvFeedsIngesterQueryResult.data) === null || _q === void 0 ? void 0 : _q.ingestionCsvFieldPatch) === null || _r === void 0 ? void 0 : _r.ingestion_running).toBeTruthy();
    }));
    it('should stop the CSV feeds ingester', () => __awaiter(void 0, void 0, void 0, function* () {
        var _s, _t;
        const CSV_FEED_INGESTER_TO_STOP = {
            id: singleColumnCsvFeedIngesterId,
            input: {
                key: 'ingestion_running',
                value: [false],
            }
        };
        const stopSingleColumnCsvFeedsIngesterQueryResult = yield queryAsAdmin({
            query: gql `
      mutation stopSingleColumnCsvFeedsIngester($id: ID!, $input: [EditInput!]!) {
        ingestionCsvFieldPatch(id: $id, input: $input){
          ingestion_running
        }
      }
      `,
            variables: CSV_FEED_INGESTER_TO_STOP
        });
        expect((_t = (_s = stopSingleColumnCsvFeedsIngesterQueryResult === null || stopSingleColumnCsvFeedsIngesterQueryResult === void 0 ? void 0 : stopSingleColumnCsvFeedsIngesterQueryResult.data) === null || _s === void 0 ? void 0 : _s.ingestionCsvFieldPatch) === null || _t === void 0 ? void 0 : _t.ingestion_running).toBeFalsy();
    }));
    it('should update the CSV feeds ingester', () => __awaiter(void 0, void 0, void 0, function* () {
        var _u, _v;
        const CSV_FEED_INGESTER_TO_UPDATE = {
            id: singleColumnCsvFeedIngesterId,
            input: {
                key: 'name',
                value: ['Single column CSV feed ingester'],
            }
        };
        const stopSingleColumnCsvFeedsIngesterQueryResult = yield queryAsAdmin({
            query: gql `
      mutation stopSingleColumnCsvFeedsIngester($id: ID!, $input: [EditInput!]!) {
        ingestionCsvFieldPatch(id: $id, input: $input){
          name
        }
      }
      `,
            variables: CSV_FEED_INGESTER_TO_UPDATE
        });
        expect((_v = (_u = stopSingleColumnCsvFeedsIngesterQueryResult === null || stopSingleColumnCsvFeedsIngesterQueryResult === void 0 ? void 0 : stopSingleColumnCsvFeedsIngesterQueryResult.data) === null || _u === void 0 ? void 0 : _u.ingestionCsvFieldPatch) === null || _v === void 0 ? void 0 : _v.name).toBe('Single column CSV feed ingester');
    }));
    it('should delete the CSV feeds ingester', () => __awaiter(void 0, void 0, void 0, function* () {
        var _w;
        const CSV_FEED_INGESTER_TO_DELETE = {
            id: singleColumnCsvFeedIngesterId,
        };
        const deleteSingleColumnCsvFeedsIngesterQueryResultSingleColumnCsvFeedsIngesterQueryResult = yield queryAsAdmin({
            query: gql `
      mutation deleteSingleColumnCsvFeedsIngesterQueryResultSingleColumnCsvFeedsIngester($id: ID!) {
        ingestionCsvDelete(id: $id)
      }
      `,
            variables: CSV_FEED_INGESTER_TO_DELETE
        });
        expect((_w = deleteSingleColumnCsvFeedsIngesterQueryResultSingleColumnCsvFeedsIngesterQueryResult.data) === null || _w === void 0 ? void 0 : _w.ingestionCsvDelete).toBe(singleColumnCsvFeedIngesterId);
    }));
});
