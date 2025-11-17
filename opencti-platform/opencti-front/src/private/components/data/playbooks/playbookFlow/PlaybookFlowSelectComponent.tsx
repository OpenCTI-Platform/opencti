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
import React from 'react';
import { Node } from 'reactflow';
import ItemIcon from '../../../../../components/ItemIcon';
import { useFormatter } from '../../../../../components/i18n';
import { PlaybookFlow_playbookComponents$data } from './__generated__/PlaybookFlow_playbookComponents.graphql';

type PlaybookComponents = NonNullable<PlaybookFlow_playbookComponents$data['playbookComponents']>;

interface PlaybookSelectComponentProps {
  components: PlaybookComponents
  selectedNode?: Node
  onSelect: (componentId: string) => void
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

  return (
    <div>
      <List>
        {entryComponents.map((component) => {
          return (
            <ListItemButton
              divider
              key={component.id}
              onClick={() => onSelect(component.id)}
            >
              <ListItemIcon>
                <ItemIcon type={component.icon}/>
              </ListItemIcon>
              <ListItemText
                primary={t_i18n(component.name)}
                secondary={t_i18n(component.description)}
              />
            </ListItemButton>
          );
        })}
      </List>
    </div>
  );
};

export default PlaybookFlowSelectComponent;
