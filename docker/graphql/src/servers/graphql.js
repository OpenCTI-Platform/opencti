import { ApolloServer } from 'apollo-server-express';
import { ApolloServerPluginDrainHttpServer } from 'apollo-server-core';
import http from 'http';
import depthLimit from "graphql-depth-limit";
// import { createComplexityLimitRule } from 'graphql-validation-complexity';
import { 
  DateTimeMock,
  EmailAddressMock,
  IPv4Mock,
  IPv6Mock,
  LatitudeMock,
  LongitudeMock,
  MACMock,
  PhoneNumberMock,
  PortMock,
  PositiveIntMock,
  PostalCodeMock,
  URLMock
} from 'graphql-scalars';


async function startApolloServer(app, port, schema) {
  // Required logic for integrating with Express
  const httpServer = http.createServer(app);

  // build the set of mocks
  const mocks = {
    DateTime: DateTimeMock,
    EmailAddress: EmailAddressMock,
    IPv4: IPv4Mock,
    IPv6: IPv6Mock,
    Latitude: LatitudeMock,
    Longitude: LongitudeMock,
    MAC: MACMock,
    PhoneNumber: PhoneNumberMock,
    Port: PortMock,
    PositiveInt: PositiveIntMock,
    PostalCode: PostalCodeMock,
    URL: URLMock,
    AssetLocation: () => ({
      id: 'location--befc3ca8-79a6-4d59-b535-ed53bf2f7c51',
      object_type: 'location',
      name: 'DarkLight Headquarters',
      street_address: '8201 164th Ave NE',
      city: 'Redmond',
      administrative_area: 'WA',
      postal_code: '98052',
      country: 'US'
    }),
    ExternalReference: () => ({
      source_name: 'Alienware',
      description: 'Aurora-R4 Owners manual',
      external_id: 'aurora-r4-owner',
      url: 'https://downloads.dell.com/manuals/all-products/esuprt_desktop/esuprt_alienware_dsk/alienware-aurora-r4_owner%27s%20manual_en-us.pdf'
    })
  };

  // Same ApolloServer initialization as before, plus the drain plugin.
  const server = new ApolloServer({
    schema,
    plugins: [ApolloServerPluginDrainHttpServer({ httpServer })],
    mocks,
    validationRules: [
      depthLimit(10), 
      // createComplexityLimitRule(1000)
    ],
    introspection: true
  });

  // More required logic for integrating with Express
  await server.start();
  server.applyMiddleware({
     app,

     // By default, apollo-server hosts its GraphQL endpoint at the
     // server root. However, *other* Apollo Server packages host it at
     // /graphql. Optionally provide this to match apollo-server.
     path: '/'
  });

  // Modified server startup
  await new Promise(resolve => httpServer.listen({ port: port }, resolve));
  console.log(`🚀 Server ready at http://localhost:${port}${server.graphqlPath}`);
}

export default startApolloServer ;
