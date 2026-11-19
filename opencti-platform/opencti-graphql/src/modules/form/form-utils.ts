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

// The id an option of a form holds: a plain id, or an object { value | id, label, ... } as the pickers store it
export const normalizeOptionId = (option: unknown): string | undefined => {
  if (typeof option === 'object' && option !== null) {
    const optionValue = (option as { value?: string; id?: string }).value || (option as { value?: string; id?: string }).id;
    return typeof optionValue === 'string' && optionValue.length > 0 ? optionValue : undefined;
  }
  return typeof option === 'string' && option.length > 0 ? option : undefined;
};

export const loadFormEntity = (context: AuthContext, user: AuthUser, id: string, type: string) => {
  return storeLoadById<StoreEntityForm>(context, user, id, type);
};
