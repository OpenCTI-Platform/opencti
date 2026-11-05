import { storeLoadById } from '../../../database/middleware-loader';
import type { EditInput } from '../../../generated/graphql';
import { generateStandardId, normalizeName } from '../../../schema/identifier';
import type { AuthContext, AuthUser } from '../../../types/user';
import { ConfigImportMode, type ConfigImportOptions, type ConfigImportResult } from '../../configImport/configImport-types';
import { configImportValidationReason } from '../../configImport/configImport-utils';
import { taskTemplateAdd, taskTemplateEdit } from '../../task/task-template/task-template-domain';
import { type BasicStoreEntityTaskTemplate, ENTITY_TYPE_TASK_TEMPLATE } from '../../task/task-template/task-template-types';
import { caseTemplateAdd, caseTemplateAddRelation, caseTemplateDeleteRelation, caseTemplateEdit, findAllCaseTemplates, findAllCaseTemplateTasks } from './case-template-domain';
import { type CaseTemplateImportConfiguration, caseTemplateImportSchema } from './case-template-import-schema';
import { TEMPLATE_TASK_RELATION } from './case-template-types';

export type CaseTemplateImportCode = 'invalid' | 'exists' | 'copy_unsupported' | 'unchanged' | 'ambiguous';

export type CaseTemplateImportResult = ConfigImportResult<CaseTemplateImportConfiguration, CaseTemplateImportCode>;

const refused = (
  status: 'failed' | 'skipped',
  code: CaseTemplateImportCode,
  reason: string,
  exists: boolean,
  configuration?: CaseTemplateImportConfiguration,
): CaseTemplateImportResult => ({ status, code, reason, exists, configuration });

type TaskConfiguration = NonNullable<CaseTemplateImportConfiguration['tasks']>[number];

// What the import does for a task: its template found by its name (the standard id of a task template is derived from it), and whether
// the case template already points to it
interface TaskStep {
  task: TaskConfiguration;
  existing?: BasicStoreEntityTaskTemplate;
  linked: boolean;
}

const findTaskTemplate = (context: AuthContext, user: AuthUser, name: string) => {
  return storeLoadById<BasicStoreEntityTaskTemplate>(context, user, generateStandardId(ENTITY_TYPE_TASK_TEMPLATE, { name }), ENTITY_TYPE_TASK_TEMPLATE);
};

const hasNewDescription = (task: TaskConfiguration, existing: BasicStoreEntityTaskTemplate) => {
  return task.description !== null && task.description !== undefined && task.description !== (existing.description ?? '');
};

// Reads the platform, writes nothing: the steps of the tasks of the configuration, and the tasks of the template that the configuration drops
const planTasks = async (context: AuthContext, user: AuthUser, tasks: TaskConfiguration[], currentTasks: BasicStoreEntityTaskTemplate[]) => {
  const steps: TaskStep[] = [];
  for (let index = 0; index < tasks.length; index += 1) {
    const existing = await findTaskTemplate(context, user, tasks[index].name);
    steps.push({ task: tasks[index], existing, linked: !!existing && currentTasks.some(({ id }) => id === existing.id) });
  }
  const dropped = currentTasks.filter(({ id }) => !steps.some(({ existing }) => existing?.id === id));
  return { steps, dropped };
};

const hasStepChange = ({ task, existing, linked }: TaskStep) => !existing || !linked || hasNewDescription(task, existing);

// Writes the task templates that are new or changed, and returns the ids of the task templates of the configuration
const writeTaskTemplates = async (context: AuthContext, user: AuthUser, steps: TaskStep[]) => {
  const ids: string[] = [];
  for (let index = 0; index < steps.length; index += 1) {
    const { task, existing } = steps[index];
    if (!existing) {
      ids.push((await taskTemplateAdd(context, user, { name: task.name, description: task.description ?? undefined })).id);
    } else {
      if (hasNewDescription(task, existing)) {
        await taskTemplateEdit(context, user, existing.id, [{ key: 'description', value: [task.description] }]);
      }
      ids.push(existing.id);
    }
  }
  return ids;
};

// The one place where a case template is imported: validates, finds the template by its name and writes it with its tasks.
// A refusal is a result, not an error. A dry run decides the same result and writes nothing.
// The standard id of a case template is random: it is found by its name (without its case), and several templates of the same name
// are refused, not guessed. Its tasks are task templates, found by their name and created when they do not exist.
// add: the template must not exist yet. overwrite: the template gets the description of the configuration, its tasks become the tasks of
// the configuration (the task templates that are no longer in it are not deleted, only unlinked), and the description of a task template
// that exists is the one of the configuration; a value that is null or absent leaves it untouched. A case template is its name: it has
// no copy. Several writes make one import: one that fails can leave the task templates it created, which a new import finds again.
export const importCaseTemplate = async (
  context: AuthContext,
  user: AuthUser,
  configuration: unknown,
  { mode, dryRun = false }: ConfigImportOptions,
): Promise<CaseTemplateImportResult> => {
  const parsed = caseTemplateImportSchema.safeParse(configuration);
  if (!parsed.success) {
    return refused('failed', 'invalid', configImportValidationReason(parsed.error), false);
  }
  const { name, description, tasks } = parsed.data;
  const sameName = (await findAllCaseTemplates(context, user)).filter((template) => normalizeName(template.name) === normalizeName(name));
  if (sameName.length > 1) {
    return refused('failed', 'ambiguous', 'Several case templates have this name', true, parsed.data);
  }
  const [existing] = sameName;
  if (mode === ConfigImportMode.Copy) {
    return refused('failed', 'copy_unsupported', 'A case template has no copy', !!existing, parsed.data);
  }
  if (!existing) {
    if (!dryRun) {
      const { steps } = await planTasks(context, user, tasks ?? [], []);
      await caseTemplateAdd(context, user, { name, description: description ?? undefined, tasks: await writeTaskTemplates(context, user, steps) });
    }
    return { status: 'created', exists: false, configuration: parsed.data };
  }
  if (mode === ConfigImportMode.Add) {
    return refused('failed', 'exists', 'Case template already exists', true, parsed.data);
  }
  const { steps, dropped } = tasks ? await planTasks(context, user, tasks, await findAllCaseTemplateTasks(context, user, existing.id)) : { steps: [], dropped: [] };
  const patch: EditInput[] = [];
  if (description !== null && description !== undefined && description !== (existing.description ?? '')) {
    patch.push({ key: 'description', value: [description] });
  }
  if (patch.length === 0 && dropped.length === 0 && !steps.some(hasStepChange)) {
    return refused('skipped', 'unchanged', 'Already up to date', true, parsed.data);
  }
  if (!dryRun) {
    const ids = await writeTaskTemplates(context, user, steps);
    const linkedIds = steps.filter(({ linked }) => linked).map(({ existing: template }) => template!.id);
    for (const id of ids.filter((taskId) => !linkedIds.includes(taskId))) {
      await caseTemplateAddRelation(context, user, existing.id, { toId: id, relationship_type: TEMPLATE_TASK_RELATION });
    }
    for (const task of dropped) {
      await caseTemplateDeleteRelation(context, user, existing.id, task.id, TEMPLATE_TASK_RELATION);
    }
    if (patch.length > 0) {
      await caseTemplateEdit(context, user, existing.id, patch);
    }
  }
  return { status: 'overwritten', exists: true, configuration: parsed.data };
};
