import { querySubTypes, queryAttributes } from '../database/grakn';

export const findAll = (args) => querySubTypes(args.type, args.includeParents);

export const findAttributes = (args) => queryAttributes(args.type);
