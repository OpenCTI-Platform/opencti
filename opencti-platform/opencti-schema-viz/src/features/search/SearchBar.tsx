import {
  Button,
  Chip,
  Combobox,
  ComboboxClear,
  ComboboxContent,
  ComboboxControls,
  ComboboxField,
  ComboboxInput,
  Dialog,
  DialogBody,
  DialogContent,
  DialogDescription,
  DialogTitle,
  Icon,
  Text,
} from '@filigran/design-system';
import { useCallback, useEffect, useMemo, useState } from 'react';
import { useSchemaGraphStore } from '../../state/schemaGraphStore';
import { useSchemaSearch } from './useSchemaSearch';
import './search.css';

const isMac = typeof navigator !== 'undefined' && /mac/i.test(navigator.platform);

interface PaletteItem {
  key: string;
  typeId: string;
  section: 'Recent' | 'Types' | 'Attributes';
  title: string;
  detail: string;
}

const CommandPalette = ({ onClose }: { onClose: () => void }) => {
  const schema = useSchemaGraphStore((state) => state.schema);
  const history = useSchemaGraphStore((state) => state.history);
  const pinned = useSchemaGraphStore((state) => state.pinnedTypeIds);
  const focusType = useSchemaGraphStore((state) => state.focusType);
  const toggleExpand = useSchemaGraphStore((state) => state.toggleExpand);
  const expanded = useSchemaGraphStore((state) => state.expandedTypeIds);
  const [term, setTerm] = useState('');
  const { types, attributes } = useSchemaSearch(schema, term, 40);

  const items = useMemo<PaletteItem[]>(() => {
    if (!schema) return [];
    const describe = (typeId: string) => {
      const type = schema.types.get(typeId);
      if (!type) return '';
      const parts = [type.category, `${type.attributes.length} attributes`];
      if (type.isAbstract) parts.push(`${type.childIds.length} subtypes`);
      return parts.join(' · ');
    };
    if (!term.trim()) {
      return [...history].reverse().map((typeId) => ({ key: `recent:${typeId}`, typeId, section: 'Recent', title: schema.types.get(typeId)?.label ?? typeId, detail: describe(typeId) }));
    }
    return [
      ...types.map((hit): PaletteItem => ({ key: `type:${hit.typeId}`, typeId: hit.typeId, section: 'Types', title: schema.types.get(hit.typeId)?.label ?? hit.typeId, detail: describe(hit.typeId) })),
      ...attributes.flatMap((hit) => hit.declaredBy.map(({ typeId, typeCount }): PaletteItem => ({
        key: `attribute:${hit.name}:${typeId}`,
        typeId,
        section: 'Attributes',
        title: hit.name,
        detail: `declared by ${schema.types.get(typeId)?.label ?? typeId}${typeCount > 1 ? ` · inherited by ${typeCount - 1} ${typeCount === 2 ? 'subtype' : 'subtypes'}` : ''}`,
      }))),
    ];
  }, [schema, term, types, attributes, history]);

  // The list stays open while the palette is, and its popover would swallow Escape: close the palette first.
  useEffect(() => {
    const onKeyDown = (event: KeyboardEvent) => event.key === 'Escape' && onClose();
    window.addEventListener('keydown', onKeyDown, { capture: true });
    return () => window.removeEventListener('keydown', onKeyDown, { capture: true });
  }, [onClose]);

  const choose = (item: PaletteItem | null, expand: boolean) => {
    if (!item) return;
    focusType(item.typeId);
    if (expand && !expanded.includes(item.typeId)) toggleExpand(item.typeId);
    onClose();
  };

  return (
    <Dialog open onOpenChange={(open) => !open && onClose()}>
      <DialogContent size="md" className="sv-palette">
        <DialogTitle>Search the schema</DialogTitle>
        <DialogDescription>Enter opens a type, Shift+Enter also expands its relations.</DialogDescription>
        <DialogBody>
          <Combobox<PaletteItem>
            options={items}
            value={null}
            onValueChange={(item, meta) => choose(item as PaletteItem | null, (meta.event as KeyboardEvent | MouseEvent | null)?.shiftKey ?? false)}
            inputValue={term}
            onInputChange={setTerm}
            filterOptions={(options) => options}
            groupBy={(item) => item.section}
            getOptionLabel={(item) => item.title}
            isOptionEqualToValue={(a, b) => a.key === b.key}
            keepInputOnBlur
            labelPosition="none"
            open
            onOpenChange={() => undefined}
            renderOption={(item) => (
              <span className="sv-option">
                <Text variant="content-compact-medium" as="span" className={item.section === 'Attributes' ? 'sv-mono' : undefined}>{item.title}</Text>
                <Text variant="content-caption" as="span" className="sv-option__detail sv-faint">{item.detail}</Text>
                {pinned.includes(item.typeId) && <Chip label="On canvas" severity="info" />}
              </span>
            )}
          >
            <ComboboxField startIcon={<Icon name="search" size={16} />}>
              <ComboboxInput autoFocus placeholder="A type or an attribute name…" aria-label="Search a type or an attribute" />
              <ComboboxControls>
                <ComboboxClear />
              </ComboboxControls>
            </ComboboxField>
            <ComboboxContent
              emptyMessage={term.trim() ? `No type or attribute matches “${term.trim()}”` : 'Type to search across all OpenCTI types and attributes'}
              listAriaLabel="Results"
            />
          </Combobox>
        </DialogBody>
      </DialogContent>
    </Dialog>
  );
};

/** Sidebar search trigger plus the ⌘K palette it opens. */
export const SearchBar = () => {
  const open = useSchemaGraphStore((state) => state.paletteOpen);
  const setOpen = useSchemaGraphStore((state) => state.setPaletteOpen);
  const close = useCallback(() => setOpen(false), [setOpen]);

  useEffect(() => {
    const onKeyDown = (event: KeyboardEvent) => {
      const target = event.target as HTMLElement | null;
      const typing = target?.closest('input, textarea, [contenteditable="true"]');
      if ((event.metaKey || event.ctrlKey) && event.key.toLowerCase() === 'k') {
        event.preventDefault();
        setOpen(true);
      } else if (event.key === '/' && !typing) {
        event.preventDefault();
        setOpen(true);
      }
    };
    window.addEventListener('keydown', onKeyDown);
    return () => window.removeEventListener('keydown', onKeyDown);
  }, [setOpen]);

  return (
    <>
      <Button
        priority="secondary"
        fullWidth
        startIcon={<Icon name="search" size={16} />}
        endIcon={<Text variant="content-caption" as="span" className="sv-faint">{isMac ? '⌘K' : 'Ctrl K'}</Text>}
        onClick={() => setOpen(true)}
        className="sv-search-trigger"
      >
        Search types, attributes…
      </Button>
      {open && <CommandPalette onClose={close} />}
    </>
  );
};
