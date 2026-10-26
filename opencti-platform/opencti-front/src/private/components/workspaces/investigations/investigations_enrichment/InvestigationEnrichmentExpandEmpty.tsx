import { Button, Text } from '@filigran/design-system';
import { DialogActions, Stack } from '@mui/material';
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
    <Stack spacing={3} sx={{ p: 3 }}>
      <Stack spacing={1}>
        <Text variant="content-base-bold">
          {t_i18n('Nothing to add to the graph')}
        </Text>
        <Text variant="content-compact">
          {t_i18n('Everything this enrichment touched is already in the graph, or it touched nothing that can be drawn.')}
        </Text>
      </Stack>

      <DialogActions>
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
      </DialogActions>
    </Stack>
  );
};

export default InvestigationEnrichmentExpandEmpty;
