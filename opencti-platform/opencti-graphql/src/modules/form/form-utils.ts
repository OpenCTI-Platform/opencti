import type { StoreEntity } from '../../types/store';

export const convertIdentityClass = (entityType: string, entity: StoreEntity) => {
  if (entityType === 'Individual') {
    entity.identity_class = 'individual';
  } else if (entityType === 'Sector') {
    entity.identity_class = 'class';
  } else if (entityType === 'System') {
    entity.identity_class = 'system';
  }
};
