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

import React, { useEffect, useMemo, useRef, useState } from 'react';
import List from '@mui/material/List';
import ListSubheader from '@mui/material/ListSubheader';
import { ListItemButton } from '@mui/material';
import ListItemIcon from '@mui/material/ListItemIcon';
import ListItemText from '@mui/material/ListItemText';
import { SearchField } from '@filigran/design-system';
import ItemIcon from '../../../../../components/ItemIcon';
import { useFormatter } from '../../../../../components/i18n';
import { PlaybookComponent, PlaybookComponents, PlaybookNode } from '../types/playbook-types';
import { filterPlaybookComponentGroups, groupAndSortPlaybookComponents } from './playbookComponents-utils';

interface PlaybookSelectComponentProps {
  components: PlaybookComponents;
  selectedNode: PlaybookNode | null;
  onSelect: (component: PlaybookComponent) => void;
}

// The searchable component palette: type to filter (name and description, every word), arrow keys to move,
// Enter to pick. The categories stay in their fixed order and the components in name order.
const PlaybookFlowSelectComponent = ({
  components,
  selectedNode,
  onSelect,
}: PlaybookSelectComponentProps) => {
  const { t_i18n } = useFormatter();
  const [search, setSearch] = useState('');
  const [active, setActive] = useState(0);
  const searchRef = useRef<HTMLInputElement>(null);
  // The palette opens on a user action (add, insert, replace): the search takes the focus so typing filters at once.
  useEffect(() => {
    searchRef.current?.focus();
  }, []);

  const isSelectedNodeEntryPoint = selectedNode?.data?.component?.is_entry_point ?? false;
  const grouped = useMemo(
    () => filterPlaybookComponentGroups(groupAndSortPlaybookComponents(components, isSelectedNodeEntryPoint), search, t_i18n),
    [components, isSelectedNodeEntryPoint, search, t_i18n],
  );
  const flat = grouped.flatMap(({ items }) => items);
  const activeIndex = Math.min(active, Math.max(0, flat.length - 1));

  const onKeyDown = (event: React.KeyboardEvent) => {
    if (event.key === 'ArrowDown') {
      event.preventDefault();
      setActive(Math.min(activeIndex + 1, flat.length - 1));
    } else if (event.key === 'ArrowUp') {
      event.preventDefault();
      setActive(Math.max(activeIndex - 1, 0));
    } else if (event.key === 'Enter' && flat[activeIndex]) {
      event.preventDefault();
      onSelect(flat[activeIndex]);
    }
  };

  let position = -1;
  return (
    <div onKeyDown={onKeyDown} role="presentation">
      <SearchField
        aria-label={t_i18n('Search components')}
        placeholder={t_i18n('Search components')}
        ref={searchRef}
        value={search}
        fullWidth
        onChange={(event) => {
          setSearch(event.target.value);
          setActive(0);
        }}
        onClear={() => {
          setSearch('');
          setActive(0);
        }}
      />
      {flat.length === 0 && (
        <div style={{ padding: '16px 8px' }}>{t_i18n('No component matches your search')}</div>
      )}
      <List aria-label={t_i18n('Components')}>
        {grouped.map(({ category, items }, index) => (
          <React.Fragment key={category}>
            <ListSubheader disableSticky sx={index > 0 ? { paddingTop: '8px' } : undefined}>{t_i18n(category)}</ListSubheader>
            {items.map((component) => {
              position += 1;
              const itemPosition = position;
              return (
                <ListItemButton
                  divider
                  key={component.id}
                  selected={itemPosition === activeIndex}
                  onMouseEnter={() => setActive(itemPosition)}
                  onClick={() => onSelect(component)}
                >
                  <ListItemIcon>
                    <ItemIcon type={component.icon} />
                  </ListItemIcon>
                  <ListItemText
                    primary={t_i18n(component.name)}
                    secondary={t_i18n(component.description)}
                  />
                </ListItemButton>
              );
            })}
          </React.Fragment>
        ))}
      </List>
    </div>
  );
};

export default PlaybookFlowSelectComponent;
