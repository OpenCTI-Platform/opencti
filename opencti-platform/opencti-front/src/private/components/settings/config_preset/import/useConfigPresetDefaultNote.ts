import { useFormatter } from '../../../../../components/i18n';

export interface ConfigPresetDefaultNote {
  // kept: the item is added as a copy, which is another item, and the current default stays the default.
  // becomes: the item is the default once imported, and the current default loses it
  kind: 'kept' | 'becomes';
  text: string;
}

interface ConfigPresetDefaultNoteRow {
  // The item is imported (selected, and not locked by its secrets)
  imported: boolean;
  // The item conflicts with one of the platform, is imported and its type offers several modes: the row offers the choice
  hasChoice: boolean;
  // The mode chosen for the item, none for an item that has no choice
  mode: string | null | undefined;
}

// What the row of an item that is the default of its type in the bundle says about the default of the platform (or of its entity type), in the
// import wizard and in the partial import: the import changes it, and the user sees it before applying. A type that is not listed says nothing.
// A copy of an item that exists is another item and never takes the default; any other import of the item makes it the default.
const useConfigPresetDefaultNote = () => {
  const { t_i18n } = useFormatter();
  // Literals in the calls, so that the extraction of the translation keys finds them
  const keptDefaultNotes: Record<string, string> = {
    branding: t_i18n('The platform keeps its current default theme.'),
    fintelDesigns: t_i18n('The platform keeps its current default fintel design.'),
    fintelTemplates: t_i18n('The entity type keeps its current default FINTEL template.'),
  };
  const becomesDefaultNotes: Record<string, string> = {
    fintelDesigns: t_i18n('Becomes the default fintel design of the platform.'),
    fintelTemplates: t_i18n('Becomes the default FINTEL template of its entity type.'),
  };
  return (typeKey: string, item: { isDefault: boolean; exists: boolean }, { imported, hasChoice, mode }: ConfigPresetDefaultNoteRow): ConfigPresetDefaultNote | undefined => {
    if (!item.isDefault || !imported) {
      return undefined;
    }
    const isCopy = mode === 'COPY';
    if (isCopy && hasChoice) {
      const kept = keptDefaultNotes[typeKey];
      return kept ? { kind: 'kept', text: kept } : undefined;
    }
    if (isCopy && item.exists) {
      return undefined;
    }
    const becomes = becomesDefaultNotes[typeKey];
    return becomes ? { kind: 'becomes', text: becomes } : undefined;
  };
};

export default useConfigPresetDefaultNote;
