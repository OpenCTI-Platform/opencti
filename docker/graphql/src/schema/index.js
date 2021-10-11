import typeDefs from "./typeDefs.js";
// import resolvers from "./resolvers.js";

import { makeExecutableSchema } from "@graphql-tools/schema";
import { 
  DateTimeTypeDefinition, DateTimeResolver, 
  EmailAddressTypeDefinition, EmailAddressResolver, 
  IPv4Definition, IPv4Resolver, 
  IPv6Definition, IPv6Resolver, 
  LatitudeDefinition, LatitudeResolver, 
  LongitudeDefinition, LongitudeResolver, 
  MACDefinition, MACResolver, 
  PhoneNumberTypeDefinition, PhoneNumberResolver, 
  PortDefinition, PortResolver,
  PositiveIntTypeDefinition, PositiveIntResolver,
  PostalCodeTypeDefinition, PostalCodeResolver, 
  URLTypeDefinition, URLResolver,
  VoidTypeDefinition, VoidResolver,
} from 'graphql-scalars';

export default async () => {
  let schema = makeExecutableSchema({
    typeDefs: [
      typeDefs,
      DateTimeTypeDefinition,
      EmailAddressTypeDefinition,
      IPv4Definition,
      IPv6Definition,
      LatitudeDefinition,
      LongitudeDefinition,
      MACDefinition,
      PhoneNumberTypeDefinition,
      PortDefinition,
      PositiveIntTypeDefinition,
      PostalCodeTypeDefinition,
      URLTypeDefinition,
      VoidTypeDefinition,
    ],
    resolvers: {
      DateTime: DateTimeResolver,
      EmailAddress: EmailAddressResolver,
      IPv4: IPv4Resolver,
      IPv6: IPv6Resolver,
      Latitude: LatitudeResolver,
      Longitude: LongitudeResolver,
      MAC: MACResolver,
      PhoneNumber: PhoneNumberResolver,
      Port: PortResolver,
      PositiveInt: PositiveIntResolver,
      PostalCode: PostalCodeResolver,
      URL: URLResolver,
      Void: VoidResolver,
    }
  });

  return schema;
};
