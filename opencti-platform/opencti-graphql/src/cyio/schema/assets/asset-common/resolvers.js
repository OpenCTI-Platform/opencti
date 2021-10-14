import { toSparql } from 'sparqlalgebrajs';
import { Converter } from 'graphql-to-sparql';
import { Converter as TreeConverter } from 'sparqljson-to-tree';

const assetCommonResolvers = {
  Query: {
    asset(parent, args, context, info) {
      // JSON-LD naming context that maps GraphQL names to RDF resources
      const nameContext = {

      };
      
      // retrieve GraphQL query the args argument
      const query = context.req.body['query'];

      // TODO: build the following code inside of a DataSource function
      // results = context.dataSources.Stardog.queryById( dbName, query, nameContext );

      // translate the GraphQL query into Sparql algebra
      const singularizeVariables = {};
      const algebra = await new Converter().graphqlToSparqlAlgebra( query, nameContext, { singularizeVariables } );

      // translate SPARQL algebra to SPARQL Query
      const sparql = toSparql(algebra);

      // issue SPARQL query to knowledge base
      const response = context.datasource.Stardog.queryById( dbName, sparql);

      const jsonResult = new TreeConverter().sparqlJsonResultsToTree(response, { singularizeVariables });

    },
    assetList(parent, args, context, info) {}
  },
  Mutation: {

  },
  // Map enum GraphQL values to data model required values
  AssetType: {
    operating_system: 'operating-system',
    database: 'database',
    web_server: 'web-server',
    dns_server: 'dns-server',
    email_server: 'email-server',
    directory_server: 'directory-server',
    pbx: 'pbx',
    firewall: 'firewall',
    router: 'router',
    switch: 'switch',
    storage_array: 'storage-array',
    appliance: 'appliance',
    application_software: 'application-software',
    network_device: 'network-device',
    circuit: 'circuit',
    compute_device: 'compute-device',
    workstation: 'workstation',
    server: 'server',
    network: 'network',
    service: 'service',
    software: 'software',
    physical_device: 'physical-device',
    system: 'system',
    web_site: 'web-site',
    voip_handset: 'voip-handset',
    voip_router: 'voip-router',
  },
};
  
export default assetCommonResolvers;