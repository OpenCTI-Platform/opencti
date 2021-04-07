import validator from 'validator';
import { ENTITY_HASHED_OBSERVABLE_STIX_FILE, isStixCyberObservable } from './stixCyberObservable';
import {
  ENTITY_TYPE_IDENTITY_INDIVIDUAL,
  ENTITY_TYPE_IDENTITY_ORGANIZATION,
  ENTITY_TYPE_IDENTITY_SECTOR,
  ENTITY_TYPE_LOCATION_CITY,
  ENTITY_TYPE_LOCATION_COUNTRY,
  ENTITY_TYPE_LOCATION_POSITION,
  ENTITY_TYPE_LOCATION_REGION,
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

const isStixId = (id) => id.match(/[a-z-]+--[\w-]{36}/g);
const isInternalId = (id) => validator.isUUID(id);
export const isAnId = (id) => {
  return isStixId(id) || isInternalId(id);
};

export const convertEntityTypeToStixType = (type) => {
  switch (type) {
    case ENTITY_TYPE_IDENTITY_INDIVIDUAL:
    case ENTITY_TYPE_IDENTITY_ORGANIZATION:
    case ENTITY_TYPE_IDENTITY_SECTOR:
      return 'identity';
    case ENTITY_TYPE_LOCATION_CITY:
    case ENTITY_TYPE_LOCATION_COUNTRY:
    case ENTITY_TYPE_LOCATION_REGION:
    case ENTITY_TYPE_LOCATION_POSITION:
      return 'location';
    case ENTITY_HASHED_OBSERVABLE_STIX_FILE:
      return 'file';
    default:
      return type.toLowerCase();
  }
};

export const parents = (type) => {
  // ENTITIES
  if (isStixDomainObject(type)) {
    return [ABSTRACT_STIX_DOMAIN_OBJECT, ABSTRACT_STIX_CORE_OBJECT, ABSTRACT_STIX_OBJECT, ABSTRACT_BASIC_OBJECT];
  }
  if (isStixCyberObservable(type)) {
    return [ABSTRACT_STIX_CYBER_OBSERVABLE, ABSTRACT_STIX_CORE_OBJECT, ABSTRACT_STIX_OBJECT, ABSTRACT_BASIC_OBJECT];
  }
  if (isStixMetaObject(type)) {
    return [ABSTRACT_STIX_META_OBJECT, ABSTRACT_STIX_OBJECT, ABSTRACT_BASIC_OBJECT];
  }
  if (isInternalObject(type)) {
    return [ABSTRACT_INTERNAL_OBJECT, ABSTRACT_BASIC_OBJECT];
  }
  // RELATIONS
  if (isStixCoreRelationship(type)) {
    return [ABSTRACT_STIX_CORE_RELATIONSHIP, ABSTRACT_STIX_RELATIONSHIP, ABSTRACT_BASIC_RELATIONSHIP];
  }
  if (isStixCyberObservableRelationship(type)) {
    return [ABSTRACT_STIX_CYBER_OBSERVABLE_RELATIONSHIP, ABSTRACT_STIX_RELATIONSHIP, ABSTRACT_BASIC_RELATIONSHIP];
  }
  if (isStixMetaRelationship(type)) {
    return [ABSTRACT_STIX_META_RELATIONSHIP, ABSTRACT_STIX_RELATIONSHIP, ABSTRACT_BASIC_RELATIONSHIP];
  }
  if (isStixRelationship(type)) {
    return [ABSTRACT_STIX_RELATIONSHIP, ABSTRACT_BASIC_RELATIONSHIP];
  }
  if (isInternalRelationship(type)) {
    return [ABSTRACT_INTERNAL_RELATIONSHIP, ABSTRACT_BASIC_RELATIONSHIP];
  }
  throw DatabaseError(`Cant resolve nature of ${type}`);
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
