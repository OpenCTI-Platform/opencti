import crypto from 'node:crypto';
import validator from 'validator';
import { isStixCyberObservable } from './stixCyberObservable';
import {
  ENTITY_TYPE_THREAT_ACTOR_GROUP,
  isStixDomainObject,
  isStixDomainObjectCase,
  isStixDomainObjectContainer,
  isStixDomainObjectIdentity,
  isStixDomainObjectLocation, isStixDomainObjectThreatActor,
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
  ABSTRACT_STIX_DOMAIN_OBJECT,
  ABSTRACT_STIX_META_OBJECT,
  ABSTRACT_STIX_OBJECT,
  ABSTRACT_STIX_REF_RELATIONSHIP,
  ABSTRACT_STIX_RELATIONSHIP,
  ENTITY_TYPE_CONTAINER,
  ENTITY_TYPE_IDENTITY,
  ENTITY_TYPE_LOCATION, ENTITY_TYPE_THREAT_ACTOR,
  STIX_TYPE_RELATION,
  STIX_TYPE_SIGHTING,
} from './general';
import { isInternalObject } from './internalObject';
import { isStixCoreRelationship } from './stixCoreRelationship';
import { isBasicRelationship, isStixRelationship } from './stixRelationship';
import { isInternalRelationship } from './internalRelationship';
import { isBasicObject, isStixCoreObject, isStixObject } from './stixCoreObject';
import { STIX_SIGHTING_RELATIONSHIP } from './stixSightingRelationship';
import { ENTITY_TYPE_CONTAINER_CASE } from '../modules/case/case-types';
import { isStixRefRelationship } from './stixRefRelationship';
import { ENTITY_TYPE_THREAT_ACTOR_INDIVIDUAL } from '../modules/threatActorIndividual/threatActorIndividual-types';

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

// Generate internal type from stix entity
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
    case 'threat-actor':
      switch (entity.resource_level) {
        case 'individual':
          return ENTITY_TYPE_THREAT_ACTOR_INDIVIDUAL;
        default:
          return ENTITY_TYPE_THREAT_ACTOR_GROUP;
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
    } else if (isStixObject(type)) {
      parentTypes.push(ABSTRACT_STIX_OBJECT);
      if (isStixMetaObject(type)) {
        parentTypes.push(ABSTRACT_STIX_META_OBJECT);
      } else if (isStixCoreObject(type)) {
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
          if (isStixDomainObjectCase(type)) {
            parentTypes.push(ENTITY_TYPE_CONTAINER_CASE);
          }
          if (isStixDomainObjectThreatActor(type)) {
            parentTypes.push(ENTITY_TYPE_THREAT_ACTOR);
          }
        }
        if (isStixCyberObservable(type)) {
          parentTypes.push(ABSTRACT_STIX_CYBER_OBSERVABLE);
        }
      }
    }
  } else if (isBasicRelationship(type)) {
    parentTypes.push(ABSTRACT_BASIC_RELATIONSHIP);
    if (isInternalRelationship(type)) {
      parentTypes.push(ABSTRACT_INTERNAL_RELATIONSHIP);
    } else if (isStixRelationship(type)) {
      parentTypes.push(ABSTRACT_STIX_RELATIONSHIP);
      if (isStixRefRelationship(type)) {
        parentTypes.push(ABSTRACT_STIX_REF_RELATIONSHIP);
      }
      if (isStixCoreRelationship(type)) {
        parentTypes.push(ABSTRACT_STIX_CORE_RELATIONSHIP);
      }
    }
  }
  if (parentTypes.length === 0) {
    throw DatabaseError(`Type ${type} not supported`);
  }

  return parentTypes;
};
