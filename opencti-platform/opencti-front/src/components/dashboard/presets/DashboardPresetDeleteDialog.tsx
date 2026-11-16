import { useState } from 'react';
import Button from '@common/button/Button';
import { Dialog, DialogBody, DialogContent, DialogDescription, DialogFooter, DialogTitle, Text } from '@filigran/design-system';
import { useFormatter } from '../../i18n';
import type { DashboardPreset } from '../dashboard-types';

export interface DashboardPresetDeleteDialogProps {
  open: boolean;
  preset: DashboardPreset;
  // May reject: the caller already notified the user, the dialog then stays open.
  onConfirm: () => Promise<void>;
  onClose: () => void;
}

const DashboardPresetDeleteDialog = ({ open, preset, onConfirm, onClose }: DashboardPresetDeleteDialogProps) => {
  const { t_i18n } = useFormatter();
  const [isSubmitting, setIsSubmitting] = useState(false);

  const handleConfirm = async () => {
    setIsSubmitting(true);
    try {
      await onConfirm();
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
      <DialogContent size="sm" data-testid="dashboard-preset-delete-dialog">
        <DialogTitle>
          <Text as="span" variant="title-md">{t_i18n('Delete preset')}</Text>
        </DialogTitle>
        <DialogBody>
          <div className="flex flex-col gap-2">
            <DialogDescription>
              {t_i18n('Do you want to delete the preset {name}?', { values: { name: preset.name } })}
            </DialogDescription>
            <Text variant="content-base">
              {t_i18n('The users and groups that open this dashboard on this preset will see its default values instead.')}
            </Text>
          </div>
        </DialogBody>
        <DialogFooter>
          <Button variant="secondary" onClick={onClose} disabled={isSubmitting}>{t_i18n('Cancel')}</Button>
          <Button
            intent="destructive"
            data-testid="dashboard-preset-delete-confirm"
            onClick={handleConfirm}
            disabled={isSubmitting}
          >
            {t_i18n('Delete')}
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
};

export default DashboardPresetDeleteDialog;
