import { isStixCoreRelationship } from './stixCoreRelationship';
import { isStixSightingRelationship } from './stixSightingRelationship';
import { isStixCyberObservableRelationship } from './stixCyberObservableRelationship';
import { isStixMetaRelationship } from './stixMetaRelationship';
import { isInternalRelationship } from './internalRelationship';

export const isStixRelationShipExceptMeta = (type: string) => isStixCoreRelationship(type) || isStixSightingRelationship(type);

export const isStixRelationship = (type: string) => isStixCoreRelationship(type)
  || isStixSightingRelationship(type)
  || isStixCyberObservableRelationship(type)
  || isStixMetaRelationship(type);

export const isBasicRelationship = (type: string) => isInternalRelationship(type) || isStixRelationship(type);
