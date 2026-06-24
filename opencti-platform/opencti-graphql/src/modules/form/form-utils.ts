import type { StoreEntity } from '../../types/store';
import { storeLoadById } from '../../database/middleware-loader';
import type { AuthContext, AuthUser } from '../../types/user';
import type { StoreEntityForm } from './form-types';

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

export const loadFormEntity = (context: AuthContext, user: AuthUser, id: string, type: string) => {
  return storeLoadById<StoreEntityForm>(context, user, id, type);
};
