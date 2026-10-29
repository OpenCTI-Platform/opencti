import { Button, DialogBody, DialogDescription, DialogFooter, Text } from '@filigran/design-system';
import { useFormatter } from '../../../../../components/i18n';

interface InvestigationEnrichmentExpandEmptyProps {
  onClose: () => void;
  onDismiss: () => void;
  canEdit: boolean;
}

const InvestigationEnrichmentExpandEmpty = ({
  onClose,
  onDismiss,
  canEdit,
}: InvestigationEnrichmentExpandEmptyProps) => {
  const { t_i18n } = useFormatter();

  return (
    <>
      <DialogBody>
        <div className="flex flex-col gap-2">
          <Text variant="content-base-bold">
            {t_i18n('Nothing to add to the graph')}
          </Text>
          <DialogDescription>
            {t_i18n('Everything this enrichment touched is already in the graph, or it touched nothing that can be drawn.')}
          </DialogDescription>
        </div>
      </DialogBody>

      <DialogFooter>
        <Button
          priority="secondary"
          onClick={onClose}
        >
          {t_i18n('Cancel')}
        </Button>
        <Button
          priority="primary"
          onClick={onDismiss}
          disabled={!canEdit}
        >
          {t_i18n('Dismiss')}
        </Button>
      </DialogFooter>
    </>
  );
};

export default InvestigationEnrichmentExpandEmpty;
