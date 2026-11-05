import type { ImportContext } from '../context';
import type { StixObject } from '../types';
import { convertMarkdown, pickAliases, required } from '../utils';
import { backfillFromExtension, extrasArguments, field, kw, type Kwargs, mutate, STIX_DOMAIN_EXTENSION_FIELDS } from '../kwargs';

// pycti/entities/opencti_identity.py
const ORGANIZATION_ADD = `
  mutation OrganizationAdd($input: OrganizationAddInput!) {
    organizationAdd(input: $input) { id standard_id entity_type parent_types }
  }
`;
const SECURITY_PLATFORM_ADD = `
  mutation SecurityPlatformAdd($input: SecurityPlatformAddInput!) {
    securityPlatformAdd(input: $input) { id standard_id entity_type parent_types }
  }
`;
const INDIVIDUAL_ADD = `
  mutation IndividualAdd($input: IndividualAddInput!) {
    individualAdd(input: $input) { id standard_id entity_type parent_types }
  }
`;
const SYSTEM_ADD = `
  mutation SystemAdd($input: SystemAddInput!) {
    systemAdd(input: $input) { id standard_id entity_type parent_types }
  }
`;
const IDENTITY_ADD = `
  mutation IdentityAdd($input: IdentityAddInput!) {
    identityAdd(input: $input) { id standard_id entity_type parent_types }
  }
`;

// pycti opencti_identity.py:create
export const createIdentity = async (context: ImportContext, kwargs: Kwargs) => {
  const type = kw(kwargs, 'type');
  if (type === null || kw(kwargs, 'name') === null) {
    context.logger.error('[opencti_identity] Missing parameters: type and name');
    return null;
  }
  const input: Record<string, unknown> = {
    stix_id: kw(kwargs, 'stix_id'),
    customFieldValues: kw(kwargs, 'custom_field_values'),
    createdBy: kw(kwargs, 'createdBy'),
    objectMarking: kw(kwargs, 'objectMarking'),
    objectLabel: kw(kwargs, 'objectLabel'),
    externalReferences: kw(kwargs, 'externalReferences'),
    revoked: kw(kwargs, 'revoked'),
    confidence: kw(kwargs, 'confidence'),
    lang: kw(kwargs, 'lang'),
    created: kw(kwargs, 'created'),
    modified: kw(kwargs, 'modified'),
    name: kw(kwargs, 'name'),
    description: kw(kwargs, 'description'),
    contact_information: kw(kwargs, 'contact_information'),
    roles: kw(kwargs, 'roles'),
    x_opencti_aliases: kw(kwargs, 'x_opencti_aliases'),
    x_opencti_stix_ids: kw(kwargs, 'x_opencti_stix_ids'),
    x_opencti_workflow_id: kw(kwargs, 'x_opencti_workflow_id'),
    x_opencti_modified_at: kw(kwargs, 'x_opencti_modified_at'),
    update: kw(kwargs, 'update', false),
    files: kw(kwargs, 'files'),
    filesMarkings: kw(kwargs, 'filesMarkings'),
    noTriggerImport: kw(kwargs, 'noTriggerImport'),
    embedded: kw(kwargs, 'embedded'),
    upsertOperations: kw(kwargs, 'upsert_operations'),
  };
  if (type === 'Organization') {
    input.x_opencti_organization_type = kw(kwargs, 'x_opencti_organization_type');
    input.x_opencti_reliability = kw(kwargs, 'x_opencti_reliability');
    input.x_opencti_score = kw(kwargs, 'x_opencti_score');
    return mutate(context, ORGANIZATION_ADD, 'organizationAdd', input);
  }
  if (type === 'SecurityPlatform') {
    input.security_platform_type = kw(kwargs, 'security_platform_type');
    delete input.contact_information;
    delete input.lang;
    delete input.roles;
    delete input.x_opencti_aliases;
    return mutate(context, SECURITY_PLATFORM_ADD, 'securityPlatformAdd', input);
  }
  if (type === 'Individual' || type === 'System') {
    input.objectOrganization = kw(kwargs, 'objectOrganization');
    input.x_opencti_firstname = kw(kwargs, 'x_opencti_firstname');
    input.x_opencti_lastname = kw(kwargs, 'x_opencti_lastname');
    input.x_opencti_reliability = kw(kwargs, 'x_opencti_reliability');
    return type === 'Individual' ? mutate(context, INDIVIDUAL_ADD, 'individualAdd', input) : mutate(context, SYSTEM_ADD, 'systemAdd', input);
  }
  input.type = type;
  return mutate(context, IDENTITY_ADD, 'identityAdd', input);
};

// The identity fields pycti copies from the extension before the standard ones
const IDENTITY_EXTENSION_FIELDS: [string, string][] = [
  ['x_opencti_aliases', 'aliases'],
  ['x_opencti_organization_type', 'organization_type'],
  ['security_platform_type', 'security_platform_type'],
  ['x_opencti_reliability', 'reliability'],
  ['x_opencti_score', 'score'],
  ['x_opencti_firstname', 'firstname'],
  ['x_opencti_lastname', 'lastname'],
  ...STIX_DOMAIN_EXTENSION_FIELDS,
];

// pycti identity_class to the OpenCTI identity type (Organization when absent or unknown)
const IDENTITY_CLASS_TYPES: Record<string, string> = {
  individual: 'Individual',
  class: 'Sector',
  system: 'System',
  securityplatform: 'SecurityPlatform',
};

// pycti opencti_identity.py:import_from_stix2
export const importIdentity = async (context: ImportContext, object: StixObject, extras: Kwargs, update: boolean) => {
  let type = 'Organization';
  // pycti compares identity_class with each class (==): only a str can match
  if ('identity_class' in object && typeof object.identity_class === 'string' && Object.hasOwn(IDENTITY_CLASS_TYPES, object.identity_class)) {
    type = IDENTITY_CLASS_TYPES[object.identity_class];
  }
  // The aliases backfill always sets x_opencti_aliases, so pick_aliases never reaches the other keys
  backfillFromExtension(object, IDENTITY_EXTENSION_FIELDS);
  return createIdentity(context, {
    ...extrasArguments(extras),
    type,
    stix_id: object.id,
    revoked: field(object, 'revoked'),
    confidence: field(object, 'confidence'),
    lang: field(object, 'lang'),
    created: field(object, 'created'),
    modified: field(object, 'modified'),
    name: required(object, 'name'),
    description: 'description' in object ? convertMarkdown(object.description) : null,
    contact_information: 'contact_information' in object ? convertMarkdown(object.contact_information) : null,
    roles: field(object, 'roles'),
    x_opencti_aliases: pickAliases(object),
    x_opencti_organization_type: field(object, 'x_opencti_organization_type'),
    security_platform_type: field(object, 'security_platform_type'),
    x_opencti_reliability: field(object, 'x_opencti_reliability'),
    x_opencti_score: field(object, 'x_opencti_score'),
    x_opencti_firstname: field(object, 'x_opencti_firstname'),
    x_opencti_lastname: field(object, 'x_opencti_lastname'),
    x_opencti_stix_ids: field(object, 'x_opencti_stix_ids'),
    objectOrganization: field(object, 'x_opencti_granted_refs'),
    x_opencti_workflow_id: field(object, 'x_opencti_workflow_id'),
    x_opencti_modified_at: field(object, 'x_opencti_modified_at'),
    update,
    upsert_operations: field(object, 'opencti_upsert_operations'),
  });
};
