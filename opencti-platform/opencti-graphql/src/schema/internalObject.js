import * as R from 'ramda';
import { ABSTRACT_INTERNAL_OBJECT, schemaTypes } from './general';

export const ENTITY_TYPE_SETTINGS = 'Settings';
export const ENTITY_TYPE_MIGRATION_STATUS = 'MigrationStatus';
export const ENTITY_TYPE_MIGRATION_REFERENCE = 'MigrationReference';
export const ENTITY_TYPE_TOKEN = 'Token';
export const ENTITY_TYPE_GROUP = 'Group';
export const ENTITY_TYPE_USER = 'User';
export const ENTITY_TYPE_ROLE = 'Role';
export const ENTITY_TYPE_CAPABILITY = 'Capability';
export const ENTITY_TYPE_CONNECTOR = 'Connector';
export const ENTITY_TYPE_ATTRIBUTE = 'Attribute';
const DATED_INTERNAL_OBJECTS = [
  ENTITY_TYPE_SETTINGS,
  ENTITY_TYPE_TOKEN,
  ENTITY_TYPE_GROUP,
  ENTITY_TYPE_USER,
  ENTITY_TYPE_ROLE,
  ENTITY_TYPE_CAPABILITY,
  ENTITY_TYPE_CONNECTOR,
];
const INTERNAL_OBJECTS = [
  ENTITY_TYPE_SETTINGS,
  ENTITY_TYPE_MIGRATION_STATUS,
  ENTITY_TYPE_MIGRATION_REFERENCE,
  ENTITY_TYPE_TOKEN,
  ENTITY_TYPE_GROUP,
  ENTITY_TYPE_USER,
  ENTITY_TYPE_ROLE,
  ENTITY_TYPE_CAPABILITY,
  ENTITY_TYPE_CONNECTOR,
  ENTITY_TYPE_ATTRIBUTE,
];
schemaTypes.register(ABSTRACT_INTERNAL_OBJECT, INTERNAL_OBJECTS);
export const isInternalObject = (type) => R.includes(type, INTERNAL_OBJECTS) || type === ABSTRACT_INTERNAL_OBJECT;
export const isDatedInternalObject = (type) => R.includes(type, DATED_INTERNAL_OBJECTS);
