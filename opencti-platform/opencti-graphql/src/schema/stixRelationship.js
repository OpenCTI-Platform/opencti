import { isStixCoreRelationship } from './stixCoreRelationship';
import { isStixSightingRelationship } from './stixSightingRelationship';
import { isStixCyberObservableRelationship } from './stixCyberObservableRelationship';
import { isStixMetaRelationship } from './stixMetaRelationship';
import { isInternalRelationship } from './internalRelationship';

export const isStixRelationShipExceptMeta = (type) => isStixCoreRelationship(type) || isStixSightingRelationship(type) || isStixCyberObservableRelationship(type);

export const isStixRelationship = (type) => isStixCoreRelationship(type)
  || isStixSightingRelationship(type)
  || isStixCyberObservableRelationship(type)
  || isStixMetaRelationship(type);

export const isBasicRelationship = (type) => isInternalRelationship(type) || isStixRelationship(type);
