import { querySubTypes, queryAttributes } from '../database/middleware';

export const findAll = (args) => querySubTypes(args);

export const findAttributes = (args) => queryAttributes(args.type);
