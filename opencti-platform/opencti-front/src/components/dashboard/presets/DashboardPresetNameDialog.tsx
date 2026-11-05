import { useState } from 'react';
import Button from '@common/button/Button';
import { Dialog, DialogBody, DialogContent, DialogDescription, DialogFooter, DialogTitle, Input, Text } from '@filigran/design-system';
import { useFormatter } from '../../i18n';
import type { DashboardPreset } from '../dashboard-types';

export const DASHBOARD_PRESET_NAME_MAX_LENGTH = 200;

export interface DashboardPresetNameDialogProps {
  open: boolean;
  // The names must be unique among the presets of the dashboard (case insensitive); the edited one is excluded.
  existingPresets: readonly DashboardPreset[];
  // Rename when provided, creation otherwise.
  preset?: DashboardPreset;
  // May reject: the caller already notified the user, the dialog then stays open.
  onConfirm: (name: string) => Promise<void>;
  onClose: () => void;
}

/**
 * Asks the name of a preset, when saving the current values as a new preset or renaming one.
 */
const DashboardPresetNameDialog = ({ open, existingPresets, preset, onConfirm, onClose }: DashboardPresetNameDialogProps) => {
  const { t_i18n } = useFormatter();
  const [name, setName] = useState(preset?.name ?? '');
  const [isSubmitting, setIsSubmitting] = useState(false);
  const trimmed = name.trim();
  let error: string | undefined;
  if (trimmed === '') error = t_i18n('This field is required');
  else if (trimmed.length > DASHBOARD_PRESET_NAME_MAX_LENGTH) error = t_i18n('This field is too long');
  else if (existingPresets.some((existing) => existing.id !== preset?.id && existing.name.trim().toLowerCase() === trimmed.toLowerCase())) {
    error = t_i18n('A preset with this name already exists');
  }

  const handleConfirm = async () => {
    if (error) return;
    setIsSubmitting(true);
    try {
      await onConfirm(trimmed);
      onClose();
    } catch {
      // The mutation hook already notified the user: the dialog stays open so they can retry or cancel.
    } finally {
      setIsSubmitting(false);
    }
  };

  return (
    <Dialog
      open={open}
      onOpenChange={(isOpen) => {
        if (!isOpen && !isSubmitting) onClose();
      }}
    >
      <DialogContent size="sm" data-testid="dashboard-preset-name-dialog">
        <DialogTitle>
          <Text as="span" variant="title-md">{preset ? t_i18n('Rename preset') : t_i18n('Save as preset')}</Text>
        </DialogTitle>
        <DialogBody>
          <div className="flex flex-col gap-4">
            <DialogDescription>
              {preset
                ? t_i18n('The values and the time range of the preset are kept, only its name changes.')
                : t_i18n('The current values of the variables and the time range are saved together, to be restored in one click.')}
            </DialogDescription>
            <Input
              label={t_i18n('Preset name')}
              name="dashboard-preset-name"
              value={name}
              required
              error={name !== '' ? error : undefined}
              onChange={(event) => setName(event.target.value)}
              onKeyDown={(event) => {
                if (event.key === 'Enter') {
                  event.preventDefault();
                  handleConfirm();
                }
              }}
            />
          </div>
        </DialogBody>
        <DialogFooter>
          <Button variant="secondary" onClick={onClose} disabled={isSubmitting}>{t_i18n('Cancel')}</Button>
          <Button
            data-testid="dashboard-preset-name-confirm"
            onClick={handleConfirm}
            disabled={isSubmitting || !!error}
          >
            {preset ? t_i18n('Rename') : t_i18n('Save')}
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
};

export default DashboardPresetNameDialog;
