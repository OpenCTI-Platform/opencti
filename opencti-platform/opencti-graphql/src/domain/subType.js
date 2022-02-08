import { querySubTypes, querySubType } from '../database/middleware';

export const findById = (subTypeId) => querySubType(subTypeId);

export const findAll = (args) => querySubTypes(args);
