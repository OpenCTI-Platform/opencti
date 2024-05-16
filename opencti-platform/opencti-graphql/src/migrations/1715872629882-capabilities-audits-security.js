import { executionContext, SYSTEM_USER } from '../utils/access';
import { addCapability } from '../domain/grant';

export const up = async (next) => {
  const context = executionContext('migration');
  await addCapability(
    context,
    SYSTEM_USER,
    {
      name: 'SETTINGS_SECURITYACTIVITY',
      description: 'Security Activity',
      attribute_order: 3500
    }
  );
  await addCapability(
    context,
    SYSTEM_USER,
    {
      name: 'SETTINGS_KNOWLEDGEACTIVITY',
      description: 'Knowledge Activity',
      attribute_order: 3600
    }
  );
  next();
};

export const down = async (next) => {
  next();
};
