import { querySubTypes } from '../database/grakn';

// eslint-disable-next-line import/prefer-default-export
export const findAll = (args) => querySubTypes(args.type, args.includeParents);
