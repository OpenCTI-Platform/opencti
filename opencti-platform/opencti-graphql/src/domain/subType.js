import { querySubTypes, queryAttributes, querySubType } from '../database/middleware';

export const findById = (subTypeId) => querySubType(subTypeId);

export const findAll = (args) => querySubTypes(args);

export const findAttributes = (args) => queryAttributes(args.type);
