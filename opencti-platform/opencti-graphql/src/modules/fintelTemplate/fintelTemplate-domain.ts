import { v4 as uuidv4 } from 'uuid';
import type { FileHandle } from 'fs/promises';
import type { AuthContext, AuthUser } from '../../types/user';
import type { EditInput, FintelTemplateAddInput, FintelTemplateWidget, FintelTemplateWidgetAddInput, WidgetDataSelection } from '../../generated/graphql';
import { createEntity, deleteElementById, updateAttribute } from '../../database/middleware';
import { type BasicStoreEntityFintelTemplate, ENTITY_TYPE_FINTEL_TEMPLATE } from './fintelTemplate-types';
import { publishUserAction } from '../../listener/UserActionListener';
import { notify } from '../../database/redis';
import { BUS_TOPICS, isFeatureEnabled, logApp } from '../../config/conf';
import { ForbiddenAccess, FunctionalError } from '../../config/errors';
import { storeLoadById } from '../../database/middleware-loader';
import { generateFintelTemplateExecutiveSummary } from '../../utils/fintelTemplate/__executiveSummary.template';
import { fintelTemplateIncidentResponse } from '../../utils/fintelTemplate/__incidentCase.template';
import { isEnterpriseEdition } from '../../enterprise-edition/ee';
import { extractContentFrom } from '../../utils/fileToContent';
import { isCompatibleVersionWithMinimal } from '../../utils/version';
import pjson from '../../../package.json';
import { convertWidgetsIds } from '../workspace/workspace-utils';
import { SELF_ID } from '../../utils/fintelTemplate/__fintelTemplateWidgets';

// to customize a template we need : EE, FF enabled
// but also to have the SETTINGS_SETCUSTOMIZATION capability !!
// (don't forget to check the capa if it's not done via a @auth in graphql of your function)
export const canCustomizeTemplate = async (context: AuthContext) => {
  const isEE = await isEnterpriseEdition(context);
  const isFileFromTemplateEnabled = isFeatureEnabled('FILE_FROM_TEMPLATE');
  if (!isEE || !isFileFromTemplateEnabled) {
    throw ForbiddenAccess();
  }
};

export const canViewTemplates = async (context: AuthContext) => {
  const isEE = await isEnterpriseEdition(context);
  const isFileFromTemplateEnabled = isFeatureEnabled('FILE_FROM_TEMPLATE');
  return !(!isEE || !isFileFromTemplateEnabled);
};

export const findById = async (context: AuthContext, user: AuthUser, id: string): Promise<BasicStoreEntityFintelTemplate> => {
  await canViewTemplates(context);
  return storeLoadById(context, user, id, ENTITY_TYPE_FINTEL_TEMPLATE);
};

// check validity of variable_name of fintel template widgets
export const checkFintelTemplateWidgetsValidity = (fintelTemplateWidgets: FintelTemplateWidget[]) => {
  const invalidVariableNames: string[] = [];
  const regex = /^[A-Za-z0-9_-]+$/;
  (fintelTemplateWidgets ?? [])
    .forEach(({ variable_name, widget }) => {
      if (!regex.test(variable_name)) {
        invalidVariableNames.push(variable_name);
      }
      if (widget.type === 'attribute') {
        widget.dataSelection.forEach((selection: WidgetDataSelection) => {
          (selection.columns ?? [])
            .forEach((c) => {
              if (!c.variableName) {
                throw FunctionalError('Attributes should all have a variable name', { variableNameOfTheWidget: variable_name });
              } else if (!regex.test(c.variableName)) {
                invalidVariableNames.push(c.variableName);
              }
            });
        });
      }
    });
  if (invalidVariableNames.length > 0) {
    throw FunctionalError('Variable names should not contain spaces or special chars (except - and _)', { invalidVariableNames });
  }
};

export const addFintelTemplate = async (
  context: AuthContext,
  user: AuthUser,
  input: FintelTemplateAddInput,
) => {
  // check rights
  await canCustomizeTemplate(context);
  // check input validity
  checkFintelTemplateWidgetsValidity(input.fintel_template_widgets ?? []);
  // add id to fintel template widgets
  const widgetsWithIds = (input.fintel_template_widgets ?? []).map((templateWidget) => ({
    ...templateWidget,
    widget: { ...templateWidget.widget, id: uuidv4() },
  }));
  // add built-in attributes widget for self instance
  widgetsWithIds.push({
    variable_name: 'widgetSelfAttributes',
    widget: {
      id: uuidv4(),
      type: 'attribute',
      perspective: null,
      dataSelection: [{
        columns: [{
          label: 'Representative',
          attribute: 'representative.main',
          variableName: 'containerRepresentative'
        }],
        instance_id: SELF_ID,
      }],
      parameters: {
        title: 'Attributes of the instance',
        description: 'Multi attributes widget for the instance which the template is applied to.',
      }
    },
  });

  const finalInput: FintelTemplateAddInput = {
    ...input,
    template_content: input.template_content ?? '',
    fintel_template_widgets: widgetsWithIds,
  };
  // create the fintel template
  const created = await createEntity(
    context,
    user,
    finalInput,
    ENTITY_TYPE_FINTEL_TEMPLATE,
  );
  return notify(BUS_TOPICS[ENTITY_TYPE_FINTEL_TEMPLATE].ADDED_TOPIC, created, user);
};

export const fintelTemplateEditField = async (
  context: AuthContext,
  user: AuthUser,
  templateId: string,
  input: EditInput[],
) => {
  // check rights
  await canCustomizeTemplate(context);
  // for add and replace operations on widgets, check fintel template widgets variables names and add widget ids
  const formattedInput = input.map((i) => {
    if (i.operation !== 'remove'
      && i.key === 'fintel_template_widgets'
      && (!i.object_path || i.object_path.split('/').length <= 2)
    ) {
      const values = i.value as FintelTemplateWidgetAddInput[];
      checkFintelTemplateWidgetsValidity(values);
      const formattedValues = values.map((v) => ({
        ...v,
        widget: { ...v.widget, id: v.widget.id ?? uuidv4() }, // ensure widget has an id
      }));
      return { ...i, value: formattedValues };
    }
    return i;
  });
  // edit the fintel template
  const { element } = await updateAttribute(
    context,
    user,
    templateId,
    ENTITY_TYPE_FINTEL_TEMPLATE,
    formattedInput,
  );

  await publishUserAction({
    user,
    event_type: 'mutation',
    event_scope: 'update',
    event_access: 'administration',
    message: 'Update template',
    context_data: { id: element.id, entity_type: ENTITY_TYPE_FINTEL_TEMPLATE, input: formattedInput },
  });

  return notify(BUS_TOPICS[ENTITY_TYPE_FINTEL_TEMPLATE].EDIT_TOPIC, element, user);
};

export const fintelTemplateDelete = async (context: AuthContext, user: AuthUser, templateId: string) => {
  await canCustomizeTemplate(context);
  const deleted = await deleteElementById(
    context,
    user,
    templateId,
    ENTITY_TYPE_FINTEL_TEMPLATE,
  );

  await publishUserAction({
    user,
    event_type: 'mutation',
    event_scope: 'delete',
    event_access: 'extended',
    message: `deletes template \`${deleted.name}\``,
    context_data: {
      id: deleted.id,
      entity_type: ENTITY_TYPE_FINTEL_TEMPLATE,
      input: deleted,
    },
  });

  return notify(BUS_TOPICS[ENTITY_TYPE_FINTEL_TEMPLATE].DELETE_TOPIC, deleted, user).then(() => templateId);
};

export const initFintelTemplates = async (context: AuthContext, user: AuthUser) => {
  const builtInTemplatesInputs = [
    generateFintelTemplateExecutiveSummary('Report'),
    generateFintelTemplateExecutiveSummary('Grouping'),
    fintelTemplateIncidentResponse,
    generateFintelTemplateExecutiveSummary('Case-Incident'),
    generateFintelTemplateExecutiveSummary('Case-Rfi'),
    generateFintelTemplateExecutiveSummary('Case-Rft')
  ];
  // add id to fintel template widgets
  const finalInputs: FintelTemplateAddInput[] = builtInTemplatesInputs.map((input) => ({
    ...input,
    template_content: input.template_content ?? '',
    fintel_template_widgets: (input.fintel_template_widgets ?? []).map((templateWidget) => ({
      ...templateWidget,
      widget: { ...templateWidget.widget, id: uuidv4() },
    })),
  }));
  await Promise.all(finalInputs
    .map((input) => createEntity(context, user, input, ENTITY_TYPE_FINTEL_TEMPLATE)));
};

const MINIMAL_VERSION_FOR_IMPORT = '6.5.0';

export const fintelTemplateExport = async (context: AuthContext, user: AuthUser, template: BasicStoreEntityFintelTemplate) => {
  const {
    name,
    description,
    settings_types,
    instance_filters,
    template_content,
    start_date,
    fintel_template_widgets,
  } = template;

  const widgets = fintel_template_widgets.map(({ widget }) => ({
    ...widget,
    dataSelection: widget.dataSelection.map((selection) => ({
      ...selection,
      filters: JSON.parse(selection.filters ?? '{}'),
      dynamicFrom: JSON.parse(selection.dynamicFrom ?? '{}'),
      dynamicTo: JSON.parse(selection.dynamicTo ?? '{}')
    }))
  }));
  await convertWidgetsIds(context, user, widgets, 'internal');
  const exportWidgets = fintel_template_widgets.map(({ variable_name }, i) => ({
    variable_name,
    widget: widgets[i]
  }));

  return JSON.stringify({
    openCTI_version: pjson.version,
    type: 'fintelTemplate',
    configuration: {
      name,
      description,
      settings_types,
      instance_filters,
      template_content,
      start_date,
      fintel_template_widgets: exportWidgets
    }
  });
};

export const fintelTemplateImport = async (context: AuthContext, user: AuthUser, file: Promise<FileHandle>) => {
  const parsedData = await extractContentFrom(file);
  logApp.debug('import fintel template', parsedData);

  if (!isCompatibleVersionWithMinimal(parsedData.openCTI_version, MINIMAL_VERSION_FOR_IMPORT)) {
    throw FunctionalError(
      `Invalid version of the platform. Please upgrade your OpenCTI. Minimal version required: ${MINIMAL_VERSION_FOR_IMPORT}`,
      { reason: parsedData.openCTI_version },
    );
  }

  return 'pouet';
};
