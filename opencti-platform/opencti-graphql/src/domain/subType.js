import { querySubTypes, queryAttributes } from '../database/grakn';

// eslint-disable-next-line import/prefer-default-export
export const findAll = (args) => querySubTypes(args.type, args.includeParents);

export const findAttributes = (args) => queryAttributes(args.type);
