import { ProgressBar } from '@filigran/design-system';
import Box from '@mui/material/Box';
import { useFormatter } from '../../../../components/i18n';
import { confidenceTone, formatPercent } from './curationUtils';

interface CurationConfidenceProps {
  value: number;
  ambiguous?: boolean;
  width?: number | string;
}

const CurationConfidence = ({ value, ambiguous = false, width = '100%' }: CurationConfidenceProps) => {
  const { t_i18n } = useFormatter();
  const decision = t_i18n('Needs your decision: the evidence is not conclusive');
  return (
    <Box
      sx={{ display: 'flex', alignItems: 'center', gap: 1, width }}
      title={ambiguous ? decision : undefined}
    >
      <Box sx={{ flex: 1 }}>
        <ProgressBar
          value={Math.round(Math.min(1, Math.max(0, value)) * 100)}
          tone={confidenceTone(value)}
          aria-label={ambiguous ? `${t_i18n('Curation confidence')}, ${decision}` : t_i18n('Curation confidence')}
        />
      </Box>
      <span style={{ minWidth: 38, textAlign: 'right' }}>{formatPercent(value)}</span>
      {ambiguous && <span aria-hidden={true}>?</span>}
    </Box>
  );
};

export default CurationConfidence;
