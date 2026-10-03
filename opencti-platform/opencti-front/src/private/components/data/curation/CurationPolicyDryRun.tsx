import { Suspense } from 'react';
import { graphql, useLazyLoadQuery } from 'react-relay';
import { Link } from 'react-router';
import Box from '@mui/material/Box';
import DialogActions from '@mui/material/DialogActions';
import Table from '@mui/material/Table';
import TableBody from '@mui/material/TableBody';
import TableCell from '@mui/material/TableCell';
import TableRow from '@mui/material/TableRow';
import Typography from '@mui/material/Typography';
import Button from '@common/button/Button';
import Dialog from '@common/dialog/Dialog';
import Label from '@common/label/Label';
import { useFormatter } from '../../../../components/i18n';
import Loader, { LoaderVariant } from '../../../../components/Loader';
import CurationConfidence from './CurationConfidence';
import useCurationLabels, { CURATION_PROPOSALS_PATH } from './curationUtils';
import { CurationPolicyDryRunQuery } from './__generated__/CurationPolicyDryRunQuery.graphql';

const dryRunQuery = graphql`
  query CurationPolicyDryRunQuery($id: ID!) {
    curationPolicyDryRun(id: $id) {
      computed_at
      eligible_count
      excluded_count
      estimated_impact {
        key
        count
      }
      exclusions {
        key
        count
      }
      sample_proposals {
        id
        name
        proposal_kind
        confidence_score
      }
    }
  }
`;

const CountTable = ({ title, entries, render }: { title: string; entries: ReadonlyArray<{ key: string; count: number }>; render: (key: string) => string }) => {
  const { t_i18n, n } = useFormatter();
  return (
    <div>
      <Label>{title}</Label>
      {entries.length === 0 ? <Typography variant="body2">{t_i18n('None')}</Typography> : (
        <Table size="small" aria-label={title}>
          <TableBody>
            {entries.map((entry) => (
              <TableRow key={entry.key}>
                <TableCell>{render(entry.key)}</TableCell>
                <TableCell align="right">{n(entry.count)}</TableCell>
              </TableRow>
            ))}
          </TableBody>
        </Table>
      )}
    </div>
  );
};

const DryRunContent = ({ policyId }: { policyId: string }) => {
  const { t_i18n, n, fldt } = useFormatter();
  const labels = useCurationLabels();
  const { curationPolicyDryRun } = useLazyLoadQuery<CurationPolicyDryRunQuery>(dryRunQuery, { id: policyId }, { fetchPolicy: 'network-only' });
  if (!curationPolicyDryRun) {
    return <Typography variant="body2">{t_i18n('No data')}</Typography>;
  }
  return (
    <Box sx={{ display: 'flex', flexDirection: 'column', gap: 2 }} data-testid="curation-policy-dry-run">
      <Typography variant="body2">
        {n(curationPolicyDryRun.eligible_count)} {t_i18n('proposal(s) would be applied')}, {n(curationPolicyDryRun.excluded_count)} {t_i18n('excluded')}
        {' - '}
        {fldt(curationPolicyDryRun.computed_at)}
      </Typography>
      <Box sx={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 2 }}>
        <CountTable title={t_i18n('Estimated impact')} entries={curationPolicyDryRun.estimated_impact} render={labels.impact} />
        <CountTable title={t_i18n('Exclusions')} entries={curationPolicyDryRun.exclusions} render={labels.exclusion} />
      </Box>
      {curationPolicyDryRun.sample_proposals.length > 0 && (
        <div>
          <Label>{t_i18n('Sample of the proposals that would be applied')}</Label>
          <Table size="small" aria-label={t_i18n('Sample of the proposals that would be applied')}>
            <TableBody>
              {curationPolicyDryRun.sample_proposals.map((proposal) => (
                <TableRow key={proposal.id}>
                  <TableCell><Link to={`${CURATION_PROPOSALS_PATH}/${proposal.id}`}>{proposal.name}</Link></TableCell>
                  <TableCell>{labels.kind(proposal.proposal_kind)}</TableCell>
                  <TableCell sx={{ width: 180 }}><CurationConfidence value={proposal.confidence_score} /></TableCell>
                </TableRow>
              ))}
            </TableBody>
          </Table>
        </div>
      )}
    </Box>
  );
};

interface CurationPolicyDryRunProps {
  policyId: string | null;
  policyName?: string;
  onClose: () => void;
}

const CurationPolicyDryRun = ({ policyId, policyName, onClose }: CurationPolicyDryRunProps) => {
  const { t_i18n } = useFormatter();
  return (
    <Dialog open={!!policyId} onClose={onClose} size="large" title={`${t_i18n('Dry run')}${policyName ? ` - ${policyName}` : ''}`}>
      {policyId && (
        <Suspense fallback={<Loader variant={LoaderVariant.inElement} />}>
          <DryRunContent policyId={policyId} />
        </Suspense>
      )}
      <DialogActions>
        <Button variant="secondary" onClick={onClose}>{t_i18n('Close')}</Button>
      </DialogActions>
    </Dialog>
  );
};

export default CurationPolicyDryRun;
