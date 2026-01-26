import type { StoreEntity } from '../../types/store';

export const convertIdentityClass = (entityType: string, entity: StoreEntity) => {
  if (entityType === 'Individual') {
    entity.identity_class = 'individual';
  } else if (entityType === 'Sector') {
    entity.identity_class = 'class';
  } else if (entityType === 'System') {
    entity.identity_class = 'system';
  } else if (entityType === 'SecurityPlatform') {
    entity.identity_class = 'securityplatform';
  }
};
