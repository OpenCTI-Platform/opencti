import { isStixCyberObservable } from './stixCyberObservable';
import { isStixDomainObject } from './stixDomainObject';
import { isStixMetaObject } from './stixMetaObject';
import { isInternalObject } from './internalObject';
import { ABSTRACT_BASIC_OBJECT, ABSTRACT_STIX_CORE_OBJECT, ABSTRACT_STIX_OBJECT } from './general';
import { isStixRelationship } from './stixRelationship';

export const isStixCoreObject = (type) => isStixDomainObject(type) || isStixCyberObservable(type) || type === ABSTRACT_STIX_CORE_OBJECT;
export const isStixObject = (type) => isStixCoreObject(type) || isStixMetaObject(type) || type === ABSTRACT_STIX_OBJECT;
export const isBasicObject = (type) => isInternalObject(type) || isStixObject(type) || type === ABSTRACT_BASIC_OBJECT;
export const isStixData = (instance) => isStixObject(instance.entity_type) || isStixRelationship(instance.entity_type);
