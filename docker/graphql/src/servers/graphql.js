import { ApolloServer } from 'apollo-server-express';
import { ApolloServerPluginDrainHttpServer } from 'apollo-server-core';
import { createServer } from 'http';
// Keycloak
import configureKeycloak from './keycloak-config.js';
import cors from "cors";
import { KeycloakContext, KeycloakTypeDefs, KeycloakSchemaDirectives } from 'keycloak-connect-graphql';
// Subscription
import { execute, subscribe } from 'graphql';
import { SubscriptionServer } from 'subscriptions-transport-ws';
// Constraints
import depthLimit from "graphql-depth-limit";
// import { createComplexityLimitRule } from 'graphql-validation-complexity';
// Custom scalars
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
  URLMock,
  VoidMock,
} from 'graphql-scalars';
// build schema
import getSchema from "../schema/index.js" ;


async function startApolloServer(app, port) {
  const graphqlPath = '/graphql'

  // Required logic for integrating with Express
  const httpServer = createServer(app);
  const schema = await getSchema();

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
    Void: VoidMock,
    AssetLocation: () => ({
      id: 'location--befc3ca8-79a6-4d59-b535-ed53bf2f7c51',
      entity_type: 'location',
      name: 'DarkLight Headquarters',
      street_address: '8201 164th Ave NE',
      city: 'Redmond',
      administrative_area: 'WA',
      postal_code: '98052',
      country: 'US'
    }),
    CyioExternalReference: () => ({
      source_name: 'Alienware',
      description: 'Aurora-R4 Owners manual',
      external_id: 'aurora-r4-owner',
      url: 'https://downloads.dell.com/manuals/all-products/esuprt_desktop/esuprt_alienware_dsk/alienware-aurora-r4_owner%27s%20manual_en-us.pdf'
    }),
    ComputingDevice: () => ({
      id: 'computing-device--204d01a8-4866-4144-b7ff-a6ba40127a2d',
      asset_id: 'darklight-2021-125',
      asset_type: 'compute_device',
      asset_tag: 'MM249847',
      name: 'Paul Patrick Personal Macbook Pro',
      description: 'Macbook Pro (16-inch 2019)',
      serial_number: 'C02D20NFMD6T',
      mac_address: ['14:b1:c8:01:9c:11'],
      vendor_name: 'Apple',
      implementation_point: 'external',
      operational_status: 'operational',
      function: 'Developer laptop',
      network_id: '192.168.1.255'
    }),
    OperatingSystem: () => ({
      id: 'software--29da67b2-b7eb-4c1a-9458-348669b77a0e',
      asset_type: 'operating_system',
      asset_id: 'darklight-2021-100',
      name: 'MacOS 11.6 (20G165)',
      description: 'MacOS',
      vendor_name: 'Apple',
      version: '11.6',
    }),
  };

  // create the subscription server
  const subscriptionServer = SubscriptionServer.create(
    {
      // This is the `schema` we just created.
      schema,
      // These are imported from `graphql`.
      execute,
      subscribe,
    }, 
    {
    // This is the `httpServer` we created in a previous step.
    server: httpServer,
    // This `server` is the instance returned from `new ApolloServer`.
    // path: server.graphqlPath,
    path: graphqlPath
    }
  );
 
  // perform the standard keycloak-connect middleware setup on our app
  const { keycloak } = configureKeycloak(app, graphqlPath)  // Same ApolloServer initialization as before, plus the drain plugin.

  // Ensure entire GraphQL Api can only be accessed by authenticated users
  // app.use(graphqlPath, keycloak.protect())
  // app.use(cors());

  const server = new ApolloServer({
    schema,
    introspection: true,
    mocks,
    // plugins: [ApolloServerPluginDrainHttpServer({ httpServer })],
    plugins: [{
      async serverWillStart() {
        return {
          async drainServer() {
            subscriptionServer.close();
          }
        };
      }
    }],
    validationRules: [
      depthLimit(10), 
      // createComplexityLimitRule(1000)
    ],
    async context({req, res, connection}) {
      // 
      const kauth = new KeycloakContext({ req }, keycloak);
      const dbName = req.headers['x-cyio-client']               
      return { req, res, kauth, dbName, }
    },
  });

  // More required logic for integrating with Express
  await server.start();
  server.applyMiddleware({
     app,

     // By default, apollo-server hosts its GraphQL endpoint at the
     // server root. However, *other* Apollo Server packages host it at
     // /graphql. Optionally provide this to match apollo-server.
     path: graphqlPath
  });

  // Modified server startup
  await new Promise(resolve => httpServer.listen({ port: port }, resolve));
  console.log(`🚀 Server ready at http://localhost:${port}${server.graphqlPath}`);
}

export default startApolloServer ;
