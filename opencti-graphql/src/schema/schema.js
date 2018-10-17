import {GraphQLDateTime} from 'graphql-iso-date';
import {importSchema} from 'graphql-import'
import {mergeResolvers} from 'merge-graphql-schemas';
import {userResolvers} from '../resolvers/user';
import {makeExecutableSchema} from 'graphql-tools';

const globalResolvers = {
    DateTime: GraphQLDateTime,
};

const typeDefs = importSchema('./src/schema/opencti.graphql');

const resolvers = mergeResolvers([
    globalResolvers,
    userResolvers
]);

const schema = makeExecutableSchema({
    typeDefs,
    resolvers
});

export default schema;