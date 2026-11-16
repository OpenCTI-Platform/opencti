import { Alert, Button, DialogBody, DialogFooter, Text } from '@filigran/design-system';
import { useFormatter } from '../../../../../components/i18n';
import DisabledReasonTooltip from '@common/tooltip/DisabledReasonTooltip';

interface InvestigationEnrichmentExpandEmptyProps {
  onClose: () => void;
  onDismiss: () => void;
  onOpenGraphExpand?: () => void;
  canEdit: boolean;
  /** Why an editor cannot review the results: disables the actions and says so in their tooltip. */
  disabledReason?: string;
}

const InvestigationEnrichmentExpandEmpty = ({
  onClose,
  onDismiss,
  onOpenGraphExpand,
  canEdit,
  disabledReason,
}: InvestigationEnrichmentExpandEmptyProps) => {
  const { t_i18n } = useFormatter();
  const disabled = !canEdit || !!disabledReason;

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
                <DisabledReasonTooltip reason={disabledReason ?? null} label={t_i18n('Expand')}>
                  <Button
                    priority="secondary"
                    size="sm"
                    onClick={onOpenGraphExpand}
                    disabled={disabled}
                  >
                    {t_i18n('Expand')}
                  </Button>
                </DisabledReasonTooltip>
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
        <DisabledReasonTooltip reason={disabledReason ?? null} label={t_i18n('Mark as reviewed')}>
          <Button
            priority="primary"
            onClick={onDismiss}
            disabled={disabled}
          >
            {t_i18n('Mark as reviewed')}
          </Button>
        </DisabledReasonTooltip>
      </DialogFooter>
    </>
  );
};

export default InvestigationEnrichmentExpandEmpty;
