/*
Copyright (c) 2021-2025 Filigran SAS

This file is part of the OpenCTI Enterprise Edition ("EE") and is
licensed under the OpenCTI Enterprise Edition License (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

https://github.com/OpenCTI-Platform/opencti/blob/master/LICENSE

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
*/

import type { PlaybookCategory } from './__generated__/PlaybookFlow_playbookComponents.graphql';
import type { PlaybookComponent, PlaybookComponentConfigSchema, PlaybookComponents, PlaybookConfig } from '../types/playbook-types';
import { PlaybookFlowFormData } from './PlaybookFlowForm';
import { PlaybookUpdateAction } from './playbookFlowFields/playbookFlowFieldsActions/playbookAction-types';

export const PLAYBOOK_CATEGORY_ORDER = [
  'start_playbook',
  'transform_and_enrich',
  'share_and_access',
  'end_playbook',
] as const;

export interface PlaybookComponentGroup {
  category: PlaybookCategory;
  items: PlaybookComponent[];
}

export function groupAndSortPlaybookComponents(
  components: PlaybookComponents,
  isEntryPoint: boolean,
): PlaybookComponentGroup[] {
  const filtered = components.flatMap((component) => {
    if (!component || component.is_entry_point !== isEntryPoint) return [];
    return component;
  });

  return PLAYBOOK_CATEGORY_ORDER
    .map((category) => ({
      category,
      items: filtered
        .filter((c) => c.category === category)
        .sort((a, b) => a.name.localeCompare(b.name)),
    }))
    .filter((g) => g.items.length > 0);
}

export interface NodeData {
  name?: string | undefined;
  description?: string | undefined;
  configuration?: PlaybookConfig | undefined;
  component?: PlaybookComponent;
  openConfig: (nodeId: string) => void;
  openReplace: (nodeId: string) => void;
  openAddSibling: (nodeId: string) => void;
  openDelete: (nodeId: string) => void;
}
interface computeInitialComponentConfigValuesParams {
  action: string | null;
  currentConfig: PlaybookConfig | null;
  configurationSchema: PlaybookComponentConfigSchema | null;
  nodeData?: NodeData;
  selectedComponent?: PlaybookComponent | null;
}

export const computeInitialComponentConfigValues = ({
  action,
  currentConfig,
  nodeData,
  configurationSchema,
  selectedComponent,
}: computeInitialComponentConfigValuesParams): PlaybookFlowFormData & Record<string, unknown> => {
  const initialValues: PlaybookFlowFormData & Record<string, unknown> = {
    name: '',
    description: '',
  };

  const componentIsReplaced = action === 'replace';

  if (!currentConfig || componentIsReplaced) {
    // Get default values from schema.
    initialValues.name = selectedComponent?.name ?? '';
    initialValues.description = '';
    Object.entries(configurationSchema?.properties ?? {})
      .forEach(([propName, property]) => {
        // eslint-disable-next-line @typescript-eslint/ban-ts-comment
        // @ts-ignore
        initialValues[propName] = property.default;
        if (propName === 'actions') initialValues.actionsFormValues = [];
      });
  } else {
    // Get values from saved config.
    initialValues.name = nodeData?.component?.id === selectedComponent?.id
      ? nodeData?.name ?? ''
      : selectedComponent?.name ?? '';
    initialValues.description = nodeData?.component?.id === selectedComponent?.id
      ? nodeData?.description ?? ''
      : '';
    const actionsFormValues: PlaybookUpdateAction['value'][] = [];
    Object.entries(currentConfig)
      .sort(([keyA], [keyB]) => keyA.localeCompare(keyB))
      .forEach(([key, value]) => {
        if (/actions-\d-value/.test(key)) actionsFormValues.push(value);
        else {
          initialValues[key] = value;
        }
        initialValues.actionsFormValues = actionsFormValues;
      });
    // Ensure applyToElements defaults to 'only-main' for existing configs missing it
    // eslint-disable-next-line @typescript-eslint/ban-ts-comment
    // @ts-ignore
    if (!initialValues.applyToElements && configurationSchema?.properties?.applyToElements) {
      initialValues.applyToElements = 'only-main';
    }
  }

  return initialValues;
};
