import { type JsonMapperParsed, JsonMapperRepresentationType } from '../modules/internal/jsonMapper/jsonMapper-types';
import { ENTITY_TYPE_IDENTITY_ORGANIZATION } from '../modules/organization/organization-types';
import { IngestionAuthType } from '../generated/graphql';

// const jsonParsers: Record<string, JsonMapperParsed> = { parser4: mapper4 as JsonMapperParsed };
// eslint-disable-next-line @typescript-eslint/ban-ts-comment
// @ts-ignore
export const testIngestion5: BasicStoreEntityIngestionJson = {
  id: '8f271994-a6ab-4103-97c5-561723d0a723',
  name: 'test',
  description: 'test',
  uri: 'http://localhost:8080/v1/statement',
  verb: 'post',
  body: "SELECT * FROM observables WHERE created_at > TIMESTAMP '$created' ORDER BY created_at ASC LIMIT 40",
  json_mapper_id: 'parser4',
  // ==== Specific for api that require sub queries (like trino)
  pagination_with_sub_page: true,
  pagination_with_sub_page_attribute_path: '$.nextUri',
  pagination_with_sub_page_query_verb: 'get',
  // ======================================
  confidence_to_score: true,
  authentication_type: IngestionAuthType.None,
  authentication_value: '',
  user_id: undefined,
  ingestion_running: true,
  last_execution_date: undefined,
  query_attributes: [
    {
      type: 'data', // If attribute need to be built from the response data.
      from: '$.data[(@.length-1)][6]', // Json path the get the data from the response
      to: 'created', // Name of the final param
      data_operation: 'data', // If data is an array, choose to get the size
      state_operation: 'replace', // How to manage the parameter in the state.
      default: '2025-04-26 21:55:38.240199', // Default value for the param
      exposed: 'body', // Where attribute must be exposed
    }
  ],
  // Specific headers for the query
  headers: [
    { name: 'X-Trino-User', value: 'admin' },
    { name: 'X-Trino-Schema', value: 'jri' },
    { name: 'X-Trino-Catalog', value: 'memory' }
  ]
};

export const mapper5: Partial<JsonMapperParsed> = {
  id: 'trino-json-mapper',
  entity_type: 'JsonMapper',
  name: 'TrinoJsonMapper',
  variables: [],
  representations: [{
    id: 'orgRepresentation',
    type: JsonMapperRepresentationType.Entity,
    target: {
      entity_type: ENTITY_TYPE_IDENTITY_ORGANIZATION,
      path: '$.data'
    },
    attributes: [
      {
        key: 'name',
        mode: 'simple',
        attr_path: {
          path: '$[6]',
        },
      }
    ]
  }]
};
