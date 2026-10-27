import { useState } from 'react';
import Button from '@common/button/Button';
import { Dialog, DialogBody, DialogContent, DialogDescription, DialogFooter, DialogTitle, Text } from '@filigran/design-system';
import { useFormatter } from '../../../../../components/i18n';
import { getMainRepresentative } from '../../../../../utils/defaultRepresentatives';
import { InvestigationEnrichmentWork } from './investigation-enrichment.types';
import InvestigationEnrichmentExpandEmpty from './InvestigationEnrichmentExpandEmpty';

interface InvestigationEnrichmentAddAllDialogProps {
  work?: InvestigationEnrichmentWork;
  nothingToAdd: boolean;
  canEdit: boolean;
  onConfirm: (work: InvestigationEnrichmentWork) => Promise<void>;
  onDismiss: (workId: string) => void;
  onClose: () => void;
}

const InvestigationEnrichmentAddAllDialog = ({
  work,
  nothingToAdd,
  canEdit,
  onConfirm,
  onDismiss,
  onClose,
}: InvestigationEnrichmentAddAllDialogProps) => {
  const { t_i18n } = useFormatter();
  const [isSubmitting, setIsSubmitting] = useState(false);
  const isEmpty = nothingToAdd && !isSubmitting;

  const handleConfirm = async () => {
    if (!work) {
      return;
    }
    setIsSubmitting(true);
    try {
      await onConfirm(work);
      onClose();
    } finally {
      setIsSubmitting(false);
    }
  };

  /**
   * Marks the work as reviewed without adding anything, then closes.
   */
  const handleDismiss = () => {
    if (work) {
      onDismiss(work.id);
    }
    onClose();
  };

  return (
    <Dialog
      open={!!work}
      // Escape, the overlay and the close button must not abandon an expand in flight.
      onOpenChange={() => {
        if (!isSubmitting) onClose();
      }}
    >
      <DialogContent size="md">
        <DialogTitle>
          <Text
            as="span"
            variant="title-md"
          >
            {t_i18n('Add all to graph')}
          </Text>
        </DialogTitle>
        {isEmpty ? (
          <InvestigationEnrichmentExpandEmpty
            onClose={onClose}
            onDismiss={handleDismiss}
            canEdit={canEdit}
          />
        ) : (
          <>
            <DialogBody>
              <DialogDescription>
                {t_i18n('Do you want to add all the enrichment results of {name} to the graph? The enrichment will be marked as reviewed.', {
                  values: { name: getMainRepresentative(work?.eventSource) },
                })}
              </DialogDescription>
            </DialogBody>
            <DialogFooter>
              <Button
                variant="secondary"
                onClick={onClose}
                disabled={isSubmitting}
              >
                {t_i18n('Cancel')}
              </Button>
              <Button
                onClick={handleConfirm}
                disabled={isSubmitting}
              >
                {t_i18n('Add')}
              </Button>
            </DialogFooter>
          </>
        )}
      </DialogContent>
    </Dialog>
  );
};

export default InvestigationEnrichmentAddAllDialog;
