import { graphql, useFragment } from 'react-relay';
import { ProgressBar, Tooltip, TooltipContent, TooltipTrigger } from '@filigran/design-system';
import Box from '@mui/material/Box';
import Table from '@mui/material/Table';
import TableBody from '@mui/material/TableBody';
import TableCell from '@mui/material/TableCell';
import TableHead from '@mui/material/TableHead';
import TableRow from '@mui/material/TableRow';
import Typography from '@mui/material/Typography';
import { useTheme } from '@mui/styles';
import Card from '@common/card/Card';
import { useFormatter } from '../../../../components/i18n';
import type { Theme } from '../../../../components/Theme';
import CurationConfidence from './CurationConfidence';
import useCurationLabels, { parseJsonObject } from './curationUtils';
import { CurationProposalEvidence_proposal$key } from './__generated__/CurationProposalEvidence_proposal.graphql';

const evidenceFragment = graphql`
  fragment CurationProposalEvidence_proposal on CurationProposal {
    proposal_kind
    confidence_score
    in_ambiguous_band
    detector
    evidence {
      evidence_type
      score
      weight
      description
      details
    }
  }
`;

// Recorded only to build the translated explanation, which already shows them.
const EXPLANATION_ONLY_DETAILS = ['entity_name', 'indicator_name', 'attributed_name', 'actor_names', 'from_name', 'to_name', 'shared_count'];

const formatDetailValue = (value: unknown): string => {
  if (value === null || value === undefined) return '-';
  if (Array.isArray(value)) return value.map(formatDetailValue).join(', ');
  if (typeof value === 'object') return JSON.stringify(value);
  return String(value);
};

interface CurationProposalEvidenceProps {
  data: CurationProposalEvidence_proposal$key;
}

const CurationProposalEvidence = ({ data }: CurationProposalEvidenceProps) => {
  const theme = useTheme<Theme>();
  const { t_i18n } = useFormatter();
  const labels = useCurationLabels();
  const proposal = useFragment(evidenceFragment, data);
  const totalWeight = proposal.evidence.reduce((acc, item) => acc + Math.max(0, item.weight), 0);

  return (
    <Card title={t_i18n('Evidence details')} padding="none">
      <Box sx={{ paddingX: 3, paddingY: 2, display: 'flex', alignItems: 'center', gap: 2 }}>
        <Typography variant="body2" color={theme.palette.text.light}>
          {t_i18n('Combined confidence')}
        </Typography>
        <Box sx={{ width: 240 }}>
          <CurationConfidence value={proposal.confidence_score} ambiguous={proposal.in_ambiguous_band} />
        </Box>
        <Typography variant="body2" color={theme.palette.text.light}>
          {labels.foundBy(proposal.proposal_kind, proposal.detector)}
        </Typography>
      </Box>
      {proposal.evidence.length === 0 ? (
        <Typography variant="body2" sx={{ paddingX: 3, paddingBottom: 2 }}>{t_i18n('No evidence recorded')}</Typography>
      ) : (
        <Table size="small" aria-label={t_i18n('Evidence')} data-testid="curation-evidence-table">
          <TableHead>
            <TableRow>
              <TableCell>{t_i18n('Evidence')}</TableCell>
              <TableCell sx={{ width: 200 }}>{t_i18n('Strength')}</TableCell>
              <TableCell sx={{ width: 170 }}>{t_i18n('Share of the decision')}</TableCell>
              <TableCell>{t_i18n('Explanation')}</TableCell>
            </TableRow>
          </TableHead>
          <TableBody>
            {proposal.evidence.map((item, index) => {
              const details = parseJsonObject(item.details);
              const share = totalWeight > 0 ? Math.round((Math.max(0, item.weight) / totalWeight) * 100) : 0;
              return (
                <TableRow key={`${item.evidence_type}-${index}`}>
                  <TableCell sx={{ verticalAlign: 'top' }}>{labels.evidence(item.evidence_type)}</TableCell>
                  <TableCell sx={{ verticalAlign: 'top' }}>
                    <CurationConfidence value={item.score} />
                  </TableCell>
                  <TableCell sx={{ verticalAlign: 'top' }}>
                    <Tooltip>
                      <TooltipTrigger asChild>
                        <Box sx={{ display: 'flex', alignItems: 'center', gap: 1 }} data-testid="curation-evidence-share">
                          {item.weight > 0 ? (
                            <>
                              <Box sx={{ flex: 1 }}>
                                <ProgressBar value={share} aria-label={labels.evidence(item.evidence_type)} />
                              </Box>
                              <span style={{ minWidth: 36, textAlign: 'right' }}>{`${share}%`}</span>
                            </>
                          ) : (
                            <span>{t_i18n('Lowers the confidence')}</span>
                          )}
                        </Box>
                      </TooltipTrigger>
                      <TooltipContent>
                        {item.weight > 0
                          ? t_i18n('Weight {weight}: {share}% of the total weight', { values: { weight: item.weight.toFixed(2), share } })
                          : t_i18n('Weight {weight}: this signal counts against the proposal', { values: { weight: item.weight.toFixed(2) } })}
                      </TooltipContent>
                    </Tooltip>
                  </TableCell>
                  <TableCell sx={{ verticalAlign: 'top' }}>
                    <div>{labels.explanation(item, details)}</div>
                    {details && (
                      <Box component="dl" sx={{ margin: 0, marginTop: 0.5, color: theme.palette.text.light, typography: 'caption' }}>
                        {Object.entries(details).filter(([key]) => !EXPLANATION_ONLY_DETAILS.includes(key)).slice(0, 8).map(([key, value]) => (
                          <div key={key}>
                            <Box component="dt" sx={{ display: 'inline', fontWeight: 'fontWeightBold' }}>{key}: </Box>
                            <Box component="dd" sx={{ display: 'inline', margin: 0 }}>{formatDetailValue(value)}</Box>
                          </div>
                        ))}
                      </Box>
                    )}
                  </TableCell>
                </TableRow>
              );
            })}
          </TableBody>
        </Table>
      )}
    </Card>
  );
};

export default CurationProposalEvidence;
