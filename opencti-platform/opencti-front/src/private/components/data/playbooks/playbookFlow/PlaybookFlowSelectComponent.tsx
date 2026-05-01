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

import List from '@mui/material/List';
import { ListItemButton } from '@mui/material';
import ListItemIcon from '@mui/material/ListItemIcon';
import ListItemText from '@mui/material/ListItemText';
import ListSubheader from '@mui/material/ListSubheader';
import ItemIcon from '../../../../../components/ItemIcon';
import { useFormatter } from '../../../../../components/i18n';
import { PlaybookComponent, PlaybookComponents, PlaybookNode } from '../types/playbook-types';
import { getShortComponentDescription } from '../utils/playbookComponentDescriptions';

type PlaybookSectionComponent = {
  name: string;
  displayName?: string;
};

const normalizeComponentName = (name: string) => name.trim().toLowerCase().replace(/\s+/g, ' ');

const nonEntrySections: Array<{ title: string; components: PlaybookSectionComponent[] }> = [
  {
    title: 'Transform and Enrich',
    components: [
      { name: 'Apply predefined rule' },
      { name: 'Container Wrapper' },
      { name: 'Enrich through connector' },
      { name: 'Extract observables from indicator' },
      { name: 'Match knowledge', displayName: 'Filter Bundle' },
      { name: 'Manipulate knowledge', displayName: 'Manipulate Bundle' },
      { name: 'Promote observable to indicator' },
      { name: 'Reduce knowledge', displayName: 'Reduce Bundle' },
      { name: 'Security Coverage', displayName: 'Create Security Coverage' },
      { name: 'Log data in standard output' },
    ],
  },
  {
    title: 'Share and Access',
    components: [
      { name: 'Manage access restrictions' },
      { name: 'Remove access restrictions' },
      { name: 'Share with organizations' },
      { name: 'Unshare with organizations' },
    ],
  },
  {
    title: 'End Playbook',
    components: [
      { name: 'Send email from template' },
      { name: 'Send for ingestion', displayName: 'Send to knowledge' },
      { name: 'Send to notifier' },
    ],
  },
];

interface PlaybookSelectComponentProps {
  components: PlaybookComponents;
  selectedNode: PlaybookNode | null;
  onSelect: (component: PlaybookComponent) => void;
}

const PlaybookFlowSelectComponent = ({
  components,
  selectedNode,
  onSelect,
}: PlaybookSelectComponentProps) => {
  const { t_i18n } = useFormatter();

  const isSelectedNodeEntryPoint = selectedNode?.data?.component?.is_entry_point ?? false;
  const entryComponents = components.flatMap((component) => {
    if (!component || component.is_entry_point !== isSelectedNodeEntryPoint) return [];
    return component;
  });

  if (isSelectedNodeEntryPoint) {
    return (
      <List>
        {entryComponents.map((component) => {
          return (
            <ListItemButton
              divider
              key={component.id}
              onClick={() => onSelect(component)}
            >
              <ListItemIcon>
                <ItemIcon type={component.icon} />
              </ListItemIcon>
              <ListItemText
                primary={t_i18n(component.name)}
                secondary={t_i18n(getShortComponentDescription(component.name, component.description))}
              />
            </ListItemButton>
          );
        })}
      </List>
    );
  }

  const componentsByName = new Map(
    entryComponents.map((component) => [normalizeComponentName(component.name), component]),
  );
  const consumedComponentIds = new Set<string>();

  return (
    <List>
      {nonEntrySections.map((section) => {
        const sectionComponents = section.components
          .map((sectionComponent) => {
            const component = componentsByName.get(normalizeComponentName(sectionComponent.name));
            if (!component) return null;
            consumedComponentIds.add(component.id);
            return { component, displayName: sectionComponent.displayName ?? component.name };
          })
          .filter((item): item is { component: PlaybookComponent; displayName: string } => Boolean(item));

        if (sectionComponents.length === 0) return null;

        return (
          <div key={section.title}>
            <ListSubheader disableSticky>{t_i18n(section.title)}</ListSubheader>
            {sectionComponents.map(({ component, displayName }) => (
              <ListItemButton
                divider
                key={component.id}
                onClick={() => onSelect(component)}
              >
                <ListItemIcon>
                  <ItemIcon type={component.icon} />
                </ListItemIcon>
                <ListItemText
                  primary={t_i18n(displayName)}
                  secondary={t_i18n(getShortComponentDescription(component.name, component.description))}
                />
              </ListItemButton>
            ))}
          </div>
        );
      })}
      {entryComponents
        .filter((component) => !consumedComponentIds.has(component.id))
        .map((component) => (
          <ListItemButton
            divider
            key={component.id}
            onClick={() => onSelect(component)}
          >
            <ListItemIcon>
              <ItemIcon type={component.icon} />
            </ListItemIcon>
            <ListItemText
              primary={t_i18n(component.name)}
              secondary={t_i18n(getShortComponentDescription(component.name, component.description))}
            />
          </ListItemButton>
        ))}
    </List>
  );
};

export default PlaybookFlowSelectComponent;
