import { GraphQLDateTime } from 'graphql-iso-date';
import { importSchema } from 'graphql-import';
import { mergeResolvers } from 'merge-graphql-schemas';
import { makeExecutableSchema } from 'graphql-tools';
import userResolvers from '../resolvers/user';
import markingDefinitionResolvers from '../resolvers/markingDefinition';
import threatActorResolvers from '../resolvers/threatActor';
import intrusionSetResolvers from '../resolvers/intrusionSet';
import malwareResolvers from '../resolvers/malware';

const globalResolvers = {
  DateTime: GraphQLDateTime
};

const typeDefs = importSchema('./src/schema/opencti.graphql');

const resolvers = mergeResolvers([
  globalResolvers,
  userResolvers,
  markingDefinitionResolvers,
  threatActorResolvers,
  intrusionSetResolvers,
  malwareResolvers
]);

const schema = makeExecutableSchema({
  typeDefs,
  resolvers
});

export default schema;
