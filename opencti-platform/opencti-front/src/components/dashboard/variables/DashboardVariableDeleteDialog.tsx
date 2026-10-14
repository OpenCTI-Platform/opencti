import { useState } from 'react';
import Button from '@common/button/Button';
import { Dialog, DialogBody, DialogContent, DialogDescription, DialogFooter, DialogTitle, Text } from '@filigran/design-system';
import { useFormatter } from '../../i18n';
import type { DashboardVariable } from '../dashboard-types';

export interface DashboardVariableDeleteDialogProps {
  open: boolean;
  variable: DashboardVariable;
  // The widgets using the variable: deleting it is never blocked, they only lose their data.
  widgets: readonly { id: string; title: string }[];
  // May reject: the caller already notified the user, the dialog then stays open.
  onConfirm: () => Promise<void>;
  onClose: () => void;
}

const DashboardVariableDeleteDialog = ({ open, variable, widgets, onConfirm, onClose }: DashboardVariableDeleteDialogProps) => {
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
      // Escape, the overlay and the close button must not abandon a deletion in flight.
      onOpenChange={(isOpen) => {
        if (!isOpen && !isSubmitting) onClose();
      }}
    >
      <DialogContent size="sm" data-testid="dashboard-variable-delete-dialog">
        <DialogTitle>
          <Text as="span" variant="title-md">{t_i18n('Delete variable')}</Text>
        </DialogTitle>
        <DialogBody>
          <div className="flex flex-col gap-2">
            <DialogDescription>
              {t_i18n('Do you want to delete the variable {name}?', { values: { name: variable.name } })}
            </DialogDescription>
            {widgets.length > 0 && (
              <>
                <Text variant="content-base">{t_i18n('These widgets use this variable and will show “No data has been found”:')}</Text>
                <ul className="m-0 list-disc pl-6">
                  {widgets.map(({ id, title }) => <Text key={id} as="li" variant="content-base">{title}</Text>)}
                </ul>
              </>
            )}
          </div>
        </DialogBody>
        <DialogFooter>
          <Button variant="secondary" onClick={onClose} disabled={isSubmitting}>{t_i18n('Cancel')}</Button>
          <Button
            intent="destructive"
            data-testid="dashboard-variable-delete-confirm"
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

export default DashboardVariableDeleteDialog;
