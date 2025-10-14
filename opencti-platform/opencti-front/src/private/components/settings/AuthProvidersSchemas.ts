import { JsonSchema } from '@jsonforms/core';

const OpenIDSchema: JsonSchema = {
  $schema: 'http://json-schema.org/draft-07/schema#',
  title: 'OpenID Connect Configuration',
  type: 'object',
  required: ['issuer', 'client_id', 'client_secret', 'redirect_uris'],
  properties: {
    issuer: {
      type: 'string',
      format: 'uri',
      description: 'The issuer identifier for the OpenID provider (usually a URL).',
    },
    client_id: {
      type: 'string',
      description: 'The client ID issued by the OpenID provider.',
    },
    client_secret: {
      type: 'string',
      description: 'The client secret issued by the OpenID provider.',
    },
    redirect_uris: {
      type: 'array',
      items: {
        type: 'string',
        format: 'uri',
      },
      minItems: 1,
      description: 'URIs where the OpenID provider can redirect after authentication.',
    },
    logout_remote: {
      type: 'boolean',
      default: false,
      description: 'Enables logout from the remote OpenID provider.',
    },
    default_scopes: {
      type: 'array',
      items: {
        type: 'string',
      },
      minItems: 0,
      description: 'OpenID scopes used by default.',
    },
    organizations_default: {
      type: 'boolean',
      default: false,
      description: 'Use default organization for users.',
    },
    name_attribute: {
      type: 'string',
      default: 'name',
      description: 'Name attribute key.',
    },
    email_attribute: {
      type: 'string',
      default: 'email',
      description: 'Email attribute key.',
    },
    firstname_attribute: {
      type: 'string',
      default: 'given_name',
      description: 'Firstname attribute key.',
    },
    lastname_attribute: {
      type: 'string',
      default: 'family_name',
      description: 'Lastname attribute key.',
    },
    get_user_attributes_from_id_token: {
      type: 'boolean',
      default: false,
      description: 'Enables retrieving user attributes from the jwt token.',
    },
    auto_create_group: {
      type: 'boolean',
      default: false,
      description: 'Enables automatic group creation',
    },
    organizations_management: {
      type: 'object',
      description: 'Custom configuration to map OpenID Claims to OpenCTI Organizations',
      properties: {
        organizations_scope: {
          type: 'string',
          default: null,
          description: 'OpenID scope to fetch the attributes',
        },
        organizations_path: {
          type: 'string',
          description: 'Comma separated values of the path to access the claims',
        },
        organizations_mapping: {
          type: 'string',
          description: 'Comma separated values of the mapping with format OpenID_Group_Value:OpenCTI_Orga_Name',
        },
      },
    },
    groups_management: {
      type: 'object',
      description: 'Custom configuration to map OpenID Claims to OpenCTI Groups',
      properties: {
        groups_scope: {
          type: 'string',
          default: null,
          description: 'OpenID scope to fetch the attributes',
        },
        groups_path: {
          type: 'string',
          description: 'Comma separated values of the path to access the claims',
        },
        groups_mapping: {
          type: 'string',
          description: 'Comma separated values of the mapping with format OpenID_Group_Value:OpenCTI_Group_Name',
        },
      },
    },
  },
  additionalProperties: false,
};

export default { OpenIDConnectStrategy: OpenIDSchema } as Record<string, JsonSchema>;
