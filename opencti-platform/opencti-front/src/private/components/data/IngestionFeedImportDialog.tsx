import React, { FunctionComponent, RefObject, useEffect } from 'react';
import ConfigPresetPartialImportDialog from '@components/settings/config_preset/import/partial/ConfigPresetPartialImportDialog';
import { useFormatter } from '../../../components/i18n';

interface IngestionFeedImportDialogProps {
  open: boolean;
  onClose: () => void;
  title: string;
  // The configuration preset type of the feeds (rssFeeds...), and what the dialog calls them (already translated)
  type: string;
  itemsLabel: string;
  // The file input of the feed file import, opened from the dialog
  fileInputRef: RefObject<HTMLInputElement | null>;
  onImported?: () => void;
}

// The import of a feed: its file, as before, or the feeds of its type taken from a configuration bundle
const IngestionFeedImportDialog: FunctionComponent<IngestionFeedImportDialogProps> = ({ open, onClose, title, type, itemsLabel, fileInputRef, onImported }) => {
  const { t_i18n } = useFormatter();
  // A file picked closes the dialog: the feed file import goes on as before, with its creation drawer
  useEffect(() => {
    const input = fileInputRef.current;
    if (!open || !input) {
      return undefined;
    }
    const handleChange = () => {
      if (input.files?.length) {
        onClose();
      }
    };
    input.addEventListener('change', handleChange);
    return () => input.removeEventListener('change', handleChange);
  }, [open]);
  return (
    <ConfigPresetPartialImportDialog
      open={open}
      onClose={onClose}
      title={title}
      type={type}
      itemsLabel={itemsLabel}
      fileLabel={t_i18n('Import a feed file')}
      fileDescription={t_i18n('A feed exported as a JSON file')}
      bundleDescription={t_i18n('Select the feeds to import from a full configuration bundle (zip)')}
      onBundleImported={() => onImported?.()}
      onChooseFile={() => fileInputRef.current?.click()}
    />
  );
};

export default IngestionFeedImportDialog;
