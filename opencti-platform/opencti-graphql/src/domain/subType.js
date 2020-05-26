import { querySubTypes } from '../database/grakn';

export const findAll = (args) => querySubTypes(args.type, args.includeParents);
