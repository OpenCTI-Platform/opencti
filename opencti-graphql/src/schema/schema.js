import { GraphQLDateTime } from 'graphql-iso-date';
import { importSchema } from 'graphql-import';
import { mergeResolvers } from 'merge-graphql-schemas';
import { makeExecutableSchema } from 'graphql-tools';
import userResolvers from '../resolvers/user';
import malwareResolvers from '../resolvers/malware';

const globalResolvers = {
  DateTime: GraphQLDateTime
};

const typeDefs = importSchema('./src/schema/opencti.graphql');

const resolvers = mergeResolvers([
  globalResolvers,
  userResolvers,
  malwareResolvers
]);

const schema = makeExecutableSchema({
  typeDefs,
  resolvers
});

export default schema;
