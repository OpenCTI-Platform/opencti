import type { AuthContext, AuthUser } from '../../../types/user';
import { findAllCaseTemplateTasks } from './case-template-domain';
import type { BasicStoreEntityCaseTemplate } from './case-template-types';

const withDescription = (name: string, description?: string | null) => ({ name, ...(description !== null && description !== undefined ? { description } : {}) });

// A case template in the import format. Its tasks are the task templates it points to, written by name and description, by name:
// the platform that imports them finds them by their name. A missing description is left out.
export const getCaseTemplateConfigPresetConfiguration = async (context: AuthContext, user: AuthUser, template: BasicStoreEntityCaseTemplate) => {
  const tasks = await findAllCaseTemplateTasks(context, user, template.id);
  return {
    ...withDescription(template.name, template.description),
    tasks: [...tasks].sort((a, b) => a.name.localeCompare(b.name)).map((task) => withDescription(task.name, task.description)),
  };
};
