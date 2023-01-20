import crypto from 'node:crypto';
import validator from 'validator';
import { isStixCyberObservable } from './stixCyberObservable';
import {
  isStixDomainObject,
  isStixDomainObjectContainer,
  isStixDomainObjectIdentity,
  isStixDomainObjectLocation,
} from './stixDomainObject';
import { DatabaseError } from '../config/errors';
import { isStixMetaObject } from './stixMetaObject';
import {
  ABSTRACT_BASIC_OBJECT,
  ABSTRACT_BASIC_RELATIONSHIP,
  ABSTRACT_INTERNAL_OBJECT,
  ABSTRACT_INTERNAL_RELATIONSHIP,
  ABSTRACT_STIX_CORE_OBJECT,
  ABSTRACT_STIX_CORE_RELATIONSHIP,
  ABSTRACT_STIX_CYBER_OBSERVABLE,
  ABSTRACT_STIX_CYBER_OBSERVABLE_RELATIONSHIP,
  ABSTRACT_STIX_DOMAIN_OBJECT,
  ABSTRACT_STIX_META_OBJECT,
  ABSTRACT_STIX_META_RELATIONSHIP,
  ABSTRACT_STIX_OBJECT,
  ABSTRACT_STIX_RELATIONSHIP,
  ENTITY_TYPE_CONTAINER,
  ENTITY_TYPE_IDENTITY,
  ENTITY_TYPE_LOCATION,
} from './general';
import { isInternalObject } from './internalObject';
import { isStixCoreRelationship } from './stixCoreRelationship';
import { isStixCyberObservableRelationship } from './stixCyberObservableRelationship';
import { isStixMetaRelationship } from './stixMetaRelationship';
import { isBasicRelationship, isStixRelationship } from './stixRelationship';
import { isInternalRelationship } from './internalRelationship';
import { isBasicObject, isStixCoreObject, isStixObject } from './stixCoreObject';
import { STIX_SIGHTING_RELATIONSHIP } from './stixSightingRelationship';
import { STIX_TYPE_SIGHTING, STIX_TYPE_RELATION } from '../database/stix';

export const isStixId = (id) => id.match(/[a-z-]+--[\w-]{36}/g);
export const isInternalId = (id) => validator.isUUID(id);
export const isAnId = (id) => {
  return isStixId(id) || isInternalId(id);
};
export const shortHash = (element) => {
  const crypt = crypto.createHash('sha256');
  const hash = crypt.update(JSON.stringify(element)).digest('hex');
  return hash.slice(0, 8);
};

const pascalize = (str) => {
  return str
    .match(/[a-z0-9]+/gi)
    .map((word) => {
      return word.charAt(0).toUpperCase() + word.substr(1).toLowerCase();
    })
    .join('-');
};

export const generateInternalType = (entity) => {
  switch (entity.type) {
    case STIX_TYPE_SIGHTING:
    case 'Stix-Sighting-Relationship':
    case 'stix-sighting-relationship':
      return STIX_SIGHTING_RELATIONSHIP;
    case STIX_TYPE_RELATION:
      return ABSTRACT_STIX_CORE_RELATIONSHIP;
    case 'identity':
      switch (entity.identity_class) {
        case 'class':
          return 'Sector';
        default:
          return pascalize(entity.identity_class);
      }
    case 'location':
      return entity.x_opencti_location_type;
    case 'ipv4-addr':
      return 'IPv4-Addr';
    case 'ipv6-addr':
      return 'IPv6-Addr';
    case 'file':
      return 'StixFile';
    default:
      return pascalize(entity.type);
  }
};

export const getParentTypes = (type) => {
  const parentTypes = [];
  if (isBasicObject(type)) {
    parentTypes.push(ABSTRACT_BASIC_OBJECT);
    if (isInternalObject(type)) {
      parentTypes.push(ABSTRACT_INTERNAL_OBJECT);
      return parentTypes;
    }
    if (isStixObject(type)) {
      parentTypes.push(ABSTRACT_STIX_OBJECT);
      if (isStixMetaObject(type)) {
        parentTypes.push(ABSTRACT_STIX_META_OBJECT);
        return parentTypes;
      }
      if (isStixCoreObject(type)) {
        parentTypes.push(ABSTRACT_STIX_CORE_OBJECT);
        if (isStixDomainObject(type)) {
          parentTypes.push(ABSTRACT_STIX_DOMAIN_OBJECT);
          if (isStixDomainObjectContainer(type)) {
            parentTypes.push(ENTITY_TYPE_CONTAINER);
          }
          if (isStixDomainObjectIdentity(type)) {
            parentTypes.push(ENTITY_TYPE_IDENTITY);
          }
          if (isStixDomainObjectLocation(type)) {
            parentTypes.push(ENTITY_TYPE_LOCATION);
          }
          return parentTypes;
        }
        if (isStixCyberObservable(type)) {
          parentTypes.push(ABSTRACT_STIX_CYBER_OBSERVABLE);
          return parentTypes;
        }
      }
    }
  }
  if (isBasicRelationship(type)) {
    parentTypes.push(ABSTRACT_BASIC_RELATIONSHIP);
    if (isInternalRelationship(type)) {
      parentTypes.push(ABSTRACT_INTERNAL_RELATIONSHIP);
      return parentTypes;
    }
    if (isStixRelationship(type)) {
      parentTypes.push(ABSTRACT_STIX_RELATIONSHIP);
      if (isStixMetaRelationship(type)) {
        parentTypes.push(ABSTRACT_STIX_META_RELATIONSHIP);
      }
      if (isStixCoreRelationship(type)) {
        parentTypes.push(ABSTRACT_STIX_CORE_RELATIONSHIP);
      }
      if (isStixCyberObservableRelationship(type)) {
        parentTypes.push(ABSTRACT_STIX_CYBER_OBSERVABLE_RELATIONSHIP);
      }
      return parentTypes;
    }
  }
  throw DatabaseError(`Type ${type} not supported`);
};
