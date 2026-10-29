import { Alert, Button, DialogBody, DialogFooter, Text } from '@filigran/design-system';
import { useFormatter } from '../../../../../components/i18n';

interface InvestigationEnrichmentExpandEmptyProps {
  onClose: () => void;
  onDismiss: () => void;
  onOpenGraphExpand?: () => void;
  canEdit: boolean;
}

const InvestigationEnrichmentExpandEmpty = ({
  onClose,
  onDismiss,
  onOpenGraphExpand,
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
          {onOpenGraphExpand && (
            <Alert
              elevation={3}
              severity="info"
              title={t_i18n('Expand with data in the platform')}
              description={t_i18n('Select from the connected data already present in the platform')}
              action={(
                <Button
                  priority="secondary"
                  size="sm"
                  onClick={onOpenGraphExpand}
                  disabled={!canEdit}
                >
                  {t_i18n('Expand')}
                </Button>
              )}
            />
          )}
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
          {t_i18n('Mark as reviewed')}
        </Button>
      </DialogFooter>
    </>
  );
};

export default InvestigationEnrichmentExpandEmpty;
