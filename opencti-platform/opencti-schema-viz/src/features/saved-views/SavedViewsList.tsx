import { Alert, Button, Icon, type IconName, Input, Menu, MenuContent, MenuItem, MenuTrigger, Text } from '@filigran/design-system';
import { type FormEvent, useState } from 'react';
import type { NormalizedSchema } from '../../data/schemaTypes';
import type { SavedView, ViewIcon } from '../../state/builtinViews';
import { clsx } from 'clsx';
import { IconAction } from '../../shared/ui/IconAction';
import { useSavedViews } from './useSavedViews';
import './savedViews.css';

const VIEW_ICONS: Record<ViewIcon, IconName> = {
  layers: 'layers',
  target: 'locate-fixed',
  tree: 'list-tree',
  folder: 'folder-open',
  tag: 'tag',
  bookmark: 'bookmark',
};

const NameForm = ({ initial, submitLabel, onSubmit, onCancel }: { initial: string; submitLabel: string; onSubmit: (name: string) => void; onCancel: () => void }) => {
  const [name, setName] = useState(initial);
  const submit = (event: FormEvent) => {
    event.preventDefault();
    if (name.trim()) onSubmit(name.trim());
  };
  return (
    <form className="sv-view-form" onSubmit={submit} onKeyDown={(event) => event.key === 'Escape' && onCancel()}>
      <Input autoFocus value={name} onChange={(event) => setName(event.target.value)} placeholder="View name" aria-label="View name" maxLength={60} />
      <div className="sv-view-form__actions">
        <Button priority="tertiary" size="sm" onClick={onCancel}>Cancel</Button>
        <Button type="submit" size="sm" disabled={!name.trim()}>{submitLabel}</Button>
      </div>
    </form>
  );
};

interface ViewRowProps {
  view: SavedView;
  active: boolean;
  modified: boolean;
  onApply: () => void;
  onRename: (name: string) => void;
  onRemove: () => void;
}

const ViewRow = ({ view, active, modified, onApply, onRename, onRemove }: ViewRowProps) => {
  const [renaming, setRenaming] = useState(false);
  const [confirmingRemove, setConfirmingRemove] = useState(false);
  const typeCount = view.snapshot.pinnedTypeIds.length;

  if (renaming) {
    return <li><NameForm initial={view.name} submitLabel="Rename" onSubmit={(name) => { onRename(name); setRenaming(false); }} onCancel={() => setRenaming(false)} /></li>;
  }

  return (
    <li className={clsx('sv-row', active && 'is-selected')}>
      <button type="button" className="sv-row__main sv-view" onClick={onApply} aria-current={active}>
        <Icon name={VIEW_ICONS[view.icon]} size={20} className="sv-view__icon" />
        <span className="sv-view__text">
          <Text variant="content-compact-medium" as="span" className="sv-row__label">
            {view.name}{active && modified ? ' •' : ''}
          </Text>
          <Text variant="content-caption" as="span" className="sv-faint">
            {view.builtin ? 'Built-in · ' : ''}{typeCount} types{active && modified ? ' · modified' : ''}
          </Text>
        </span>
      </button>
      {!view.builtin && (
        <Menu onOpenChange={(open) => !open && setConfirmingRemove(false)}>
          <MenuTrigger asChild>
            <IconAction icon="ellipsis-vertical" label={`Actions for ${view.name}`} />
          </MenuTrigger>
          <MenuContent align="end">
            <MenuItem startIcon={<Icon name="pencil" size={16} />} onSelect={() => setRenaming(true)}>Rename</MenuItem>
            {confirmingRemove ? (
              <MenuItem startIcon={<Icon name="trash-2" size={16} />} onSelect={onRemove}>Confirm delete</MenuItem>
            ) : (
              <MenuItem
                startIcon={<Icon name="trash-2" size={16} />}
                onSelect={(event) => {
                  event.preventDefault();
                  setConfirmingRemove(true);
                }}
              >
                Delete…
              </MenuItem>
            )}
          </MenuContent>
        </Menu>
      )}
    </li>
  );
};

/** "Subject areas": named canvases to come back to. Built-in ones ship with the app, user ones stay in the browser. */
export const SavedViewsList = ({ schema }: { schema: NormalizedSchema }) => {
  const { views, activeView, isModified, applyView, saveAsNew, saveActive, renameView, removeView } = useSavedViews(schema);
  const [creating, setCreating] = useState(false);

  return (
    <>
      <div className="sv-section-title">
        <Text variant="title-xs" as="h2">Saved views</Text>
        {!creating && (
          <Button priority="tertiary" size="sm" startIcon={<Icon name="plus" size={16} />} onClick={() => setCreating(true)}>New</Button>
        )}
      </div>
      {creating && (
        <NameForm initial="" submitLabel="Save" onSubmit={(name) => { saveAsNew(name); setCreating(false); }} onCancel={() => setCreating(false)} />
      )}
      {activeView && !activeView.builtin && isModified && !creating && (
        <Alert
          severity="info"
          title={`Canvas changed since “${activeView.name}”`}
          action={<Button priority="secondary" size="sm" onClick={saveActive}>Update view</Button>}
          className="sv-view-modified"
        />
      )}
      <ul className="sv-views">
        {views.map((view) => (
          <ViewRow
            key={view.id}
            view={view}
            active={view.id === activeView?.id}
            modified={isModified}
            onApply={() => applyView(view)}
            onRename={(name) => renameView(view.id, name)}
            onRemove={() => removeView(view.id)}
          />
        ))}
      </ul>
    </>
  );
};
