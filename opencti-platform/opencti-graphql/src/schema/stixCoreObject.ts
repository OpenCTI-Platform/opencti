import { isStixCyberObservable } from './stixCyberObservable';
import { isStixDomainObject } from './stixDomainObject';
import { isStixMetaObject } from './stixMetaObject';
import { isInternalObject } from './internalObject';
import { ABSTRACT_BASIC_OBJECT, ABSTRACT_STIX_CORE_OBJECT, ABSTRACT_STIX_OBJECT } from './general';
import { isStixRelationshipExceptRef } from './stixRelationship';
import { RELATION_PARTICIPATE_TO } from './internalRelationship';
import type { StoreObject } from '../types/store';

export const INTERNAL_EXPORTABLE_TYPES = [RELATION_PARTICIPATE_TO];

export const isStixCoreObject = (type: string) => isStixDomainObject(type) || isStixCyberObservable(type) || type === ABSTRACT_STIX_CORE_OBJECT;
export const isStixObject = (type: string) => isStixCoreObject(type) || isStixMetaObject(type) || type === ABSTRACT_STIX_OBJECT;
export const isBasicObject = (type: string) => isInternalObject(type) || isStixObject(type) || type === ABSTRACT_BASIC_OBJECT;
export const isStixExportableData = (instance: StoreObject) => isStixObject(instance.entity_type)
  || isStixRelationshipExceptRef(instance.entity_type) || INTERNAL_EXPORTABLE_TYPES.includes(instance.entity_type);

export const stixCoreObjectOptions = {
  StixCoreObjectsOrdering: {}
};
