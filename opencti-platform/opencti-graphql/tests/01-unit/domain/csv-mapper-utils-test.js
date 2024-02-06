var __awaiter = (this && this.__awaiter) || function (thisArg, _arguments, P, generator) {
    function adopt(value) { return value instanceof P ? value : new P(function (resolve) { resolve(value); }); }
    return new (P || (P = Promise))(function (resolve, reject) {
        function fulfilled(value) { try { step(generator.next(value)); } catch (e) { reject(e); } }
        function rejected(value) { try { step(generator["throw"](value)); } catch (e) { reject(e); } }
        function step(result) { result.done ? resolve(result.value) : adopt(result.value).then(fulfilled, rejected); }
        step((generator = generator.apply(thisArg, _arguments || [])).next());
    });
};
import { assert, describe, expect, it } from 'vitest';
import { csvMapperMockSimpleDifferentEntities } from '../../data/csv-mapper-mock-simple-different-entities';
import { validate } from '../../../src/modules/internal/csvMapper/csvMapper-utils';
import { ADMIN_USER, testContext } from '../../utils/testQuery';
describe('CSV Mapper', () => {
    it('validate a valid mapper', () => __awaiter(void 0, void 0, void 0, function* () {
        yield validate(testContext, ADMIN_USER, Object.assign(Object.assign({}, csvMapperMockSimpleDifferentEntities), { name: 'Valid Mapper' }));
        assert(true);
    }));
    it('invalidate a invalid mapper', () => __awaiter(void 0, void 0, void 0, function* () {
        const mapper = csvMapperMockSimpleDifferentEntities;
        yield expect(() => validate(testContext, ADMIN_USER, Object.assign(Object.assign({}, mapper), { name: 'Invalid Mapper', representations: [] }))).rejects.toThrowError('CSV Mapper \'Invalid Mapper\' has no representation');
        yield expect(() => validate(testContext, ADMIN_USER, Object.assign(Object.assign({}, mapper), { name: 'Invalid Mapper', representations: [
                Object.assign(Object.assign({}, mapper.representations[0]), { attributes: [] }),
                mapper.representations[1],
            ] }))).rejects.toThrowError('Missing values for required attribute');
        // TODO: cover more validation tests
    }));
});
