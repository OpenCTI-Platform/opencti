import { Button, Checkbox, Icon, Text } from '@filigran/design-system';
import { useState } from 'react';
import type { NormalizedSchema } from '../../data/schemaTypes';
import { useSchemaGraphStore } from '../../state/schemaGraphStore';
import { CATEGORY_META } from '../../shared/theme/typeAppearance';
import { clsx } from 'clsx';
import { IconAction } from '../../shared/ui/IconAction';
import { SavedViewsList } from '../saved-views/SavedViewsList';
import { SearchBar } from '../search/SearchBar';
import { type CategorySummary, useTypeFilters } from './useTypeFilters';
import './filters.css';

const CategoryTypes = ({ schema, summary }: { schema: NormalizedSchema; summary: CategorySummary }) => {
  const pinnedTypeIds = useSchemaGraphStore((state) => state.pinnedTypeIds);
  const selectedTypeId = useSchemaGraphStore((state) => state.selectedTypeId);
  const focusType = useSchemaGraphStore((state) => state.focusType);
  const togglePinned = useSchemaGraphStore((state) => state.togglePinned);
  const pinTypes = useSchemaGraphStore((state) => state.pinTypes);
  const unpinTypes = useSchemaGraphStore((state) => state.unpinTypes);
  const allPinned = summary.pinnedCount === summary.typeIds.length;

  return (
    <div className="sv-category__types">
      <Button
        priority="tertiary"
        size="sm"
        onClick={() => (allPinned ? unpinTypes(summary.typeIds) : pinTypes(summary.typeIds))}
      >
        {allPinned ? 'Remove all from canvas' : `Add all ${summary.typeIds.length} to canvas`}
      </Button>
      <ul>
        {summary.typeIds.map((typeId) => {
          const type = schema.types.get(typeId);
          if (!type) return null;
          const pinned = pinnedTypeIds.includes(typeId);
          return (
            <li key={typeId} className={clsx('sv-row', selectedTypeId === typeId && 'is-selected')}>
              <button type="button" className="sv-row__main" onClick={() => focusType(typeId)}>
                <Text variant="content-compact" as="span" className={clsx('sv-row__label', type.isAbstract && 'sv-muted')}>{type.label}</Text>
              </button>
              <IconAction
                icon={pinned ? 'eye' : 'eye-off'}
                active={pinned}
                label={pinned ? `Remove ${type.label} from the canvas` : `Add ${type.label} to the canvas`}
                onClick={() => togglePinned(typeId)}
              />
            </li>
          );
        })}
      </ul>
    </div>
  );
};

const CategoryRow = ({ schema, summary }: { schema: NormalizedSchema; summary: CategorySummary }) => {
  const [open, setOpen] = useState(false);
  const setCategoryEnabled = useSchemaGraphStore((state) => state.setCategoryEnabled);
  const meta = CATEGORY_META[summary.category];

  return (
    <li className="sv-category">
      <div className="sv-category__row">
        <Checkbox
          checked={summary.enabled}
          onCheckedChange={(checked) => setCategoryEnabled(summary.category, checked === true)}
          label={meta.label}
          description={meta.description}
          wrapperClassName="sv-category__check"
        />
        <Text variant="content-caption" as="span" className="sv-faint" aria-label={`${summary.pinnedCount} of ${summary.typeIds.length} types on the canvas`}>
          {summary.pinnedCount > 0 ? `${summary.pinnedCount} / ${summary.typeIds.length}` : summary.typeIds.length}
        </Text>
        <IconAction
          icon={open ? 'chevron-down' : 'chevron-right'}
          label={open ? `Hide ${meta.description}` : `List ${meta.description}`}
          aria-expanded={open}
          onClick={() => setOpen(!open)}
        />
      </div>
      {open && <CategoryTypes schema={schema} summary={summary} />}
    </li>
  );
};

interface FilterSidebarProps {
  schema: NormalizedSchema;
  collapsed: boolean;
  onToggleCollapsed: () => void;
}

/** Left panel: search, the categories as a clickable legend, and saved views. */
export const FilterSidebar = ({ schema, collapsed, onToggleCollapsed }: FilterSidebarProps) => {
  const { categories, enabledCount } = useTypeFilters(schema);
  const setAllCategories = useSchemaGraphStore((state) => state.setAllCategories);

  if (collapsed) {
    return (
      <aside className="sv-sidebar is-collapsed" aria-label="Filters">
        <IconAction icon="panel-left-open" label="Expand the sidebar" onClick={onToggleCollapsed} size="md" />
      </aside>
    );
  }

  return (
    <aside className="sv-sidebar" aria-label="Filters">
      <div className="sv-sidebar__search">
        <SearchBar />
      </div>
      <div className="sv-sidebar__scroll">
        <section className="sv-sidebar__section">
          <div className="sv-section-title">
            <Text variant="title-xs" as="h2">Categories</Text>
            <Button priority="tertiary" size="sm" onClick={() => setAllCategories(enabledCount < categories.length)}>
              {enabledCount < categories.length ? 'Select all' : 'Clear'}
            </Button>
          </div>
          <ul className="sv-categories">
            {categories.map((summary) => <CategoryRow key={summary.category} schema={schema} summary={summary} />)}
          </ul>
          <Text variant="content-caption" as="p" className="sv-sidebar__hint sv-muted">
            Unchecked categories are hidden from the canvas. Open one to add its types.
          </Text>
        </section>
        <section className="sv-sidebar__section">
          <SavedViewsList schema={schema} />
        </section>
      </div>
      <div className="sv-sidebar__footer">
        <Button priority="tertiary" size="sm" startIcon={<Icon name="panel-left-close" size={16} />} onClick={onToggleCollapsed}>
          Collapse
        </Button>
      </div>
    </aside>
  );
};
