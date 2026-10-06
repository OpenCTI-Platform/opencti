import React, { Fragment } from 'react';
import { MenuItem, MenuLabel } from '@filigran/design-system';
import type { GraphToolbarAction } from './useGraphToolbarActions';

/**
 * A toggle or a choice of a list is a checkable item. The attributes are only spread when they
 * apply: an explicit `role={undefined}` would erase the `menuitem` role of the item.
 */
export const checkable = (checked: boolean | undefined) => (checked === undefined ? {} : { role: 'menuitemcheckbox', 'aria-checked': checked });

interface GraphToolbarOptionsListProps {
  options: NonNullable<GraphToolbarAction['options']>;
}

/**
 * The choices of a toolbar list (select by type, filters) as menu items, the same in the menu the
 * toolbar opens and in the submenu of "More actions": a heading opens each part of the list, and a
 * choice of a multiple list is checkable and leaves the menu open for the next one.
 */
const GraphToolbarOptionsList = ({ options }: GraphToolbarOptionsListProps) => {
  let section: string | undefined;
  return (
    <>
      {options.items.map((option) => {
        const heading = option.section && option.section !== section ? option.section : undefined;
        section = option.section;
        return (
          <Fragment key={option.key}>
            {heading && <MenuLabel>{heading}</MenuLabel>}
            <MenuItem
              {...checkable(options.multiple ? !!option.selected : undefined)}
              selected={!!option.selected}
              onSelect={(event) => {
                if (options.multiple) event.preventDefault();
                options.onSelect(option.key);
              }}
            >
              {option.label}
            </MenuItem>
          </Fragment>
        );
      })}
    </>
  );
};

export default GraphToolbarOptionsList;
