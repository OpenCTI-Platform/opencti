import type {Resolvers} from '../../generated/graphql';
import {initSchema, initStubs, queries} from './tidb-domain';

const tidbResolvers: Resolvers = {
    Query: {
        queries: (_, __, context) => queries(context, context.user),
    },
    Mutation: {
        initSchema: (_, __, context) => {
            return initSchema(context, context.user);
        },
        initStubs: (_, __, context) => {
            return initStubs(context, context.user);
        },
    },
};

export default tidbResolvers;