import {GraphQLDateTime} from 'graphql-iso-date';
import {importSchema} from 'graphql-import'
import {mergeResolvers} from 'merge-graphql-schemas';
import {userResolvers} from '../resolvers/user';

const globalResolvers = {
    DateTime: GraphQLDateTime,
};

export const typeDefs = importSchema('./src/schema/opencti.graphql');

export const resolvers = mergeResolvers([
    globalResolvers,
    userResolvers
]);