import { Suspense, useState } from 'react';
import { graphql, useLazyLoadQuery } from 'react-relay';
import { Link } from 'react-router';
import Box from '@mui/material/Box';
import DialogActions from '@mui/material/DialogActions';
import Table from '@mui/material/Table';
import TableBody from '@mui/material/TableBody';
import TableCell from '@mui/material/TableCell';
import TableHead from '@mui/material/TableHead';
import TableRow from '@mui/material/TableRow';
import Typography from '@mui/material/Typography';
import { useTheme } from '@mui/styles';
import { Checkbox, Tooltip, TooltipContent, TooltipTrigger } from '@filigran/design-system';
import Button from '@common/button/Button';
import Dialog from '@common/dialog/Dialog';
import Label from '@common/label/Label';
import Tag from '@common/tag/Tag';
import Drawer from '@components/common/drawer/Drawer';
import { useFormatter } from '../../../../components/i18n';
import ItemIcon from '../../../../components/ItemIcon';
import type { Theme } from '../../../../components/Theme';
import { resolveLink } from '../../../../utils/Entity';
import useApiMutation from '../../../../utils/hooks/useApiMutation';
import useGranted, { KNOWLEDGE_KNUPDATE_KNMERGE } from '../../../../utils/hooks/useGranted';
import { MESSAGING$ } from '../../../../relay/environment';
import CurationSkeleton from './CurationSkeleton';
import useCurationLabels, { CURATION_PROPOSALS_PATH, notifyPayloadErrors } from './curationUtils';
import { MergeRecordDrawerQuery } from './__generated__/MergeRecordDrawerQuery.graphql';
import { MergeRecordDrawerUnmergeMutation } from './__generated__/MergeRecordDrawerUnmergeMutation.graphql';

const mergeRecordDrawerQuery = graphql`
  query MergeRecordDrawerQuery($id: ID!) {
    mergeRecord(id: $id) {
      id
      name
      merge_status
      merge_target_id
      merge_target_type
      merge_target_name
      reversible_until
      is_reversible
      irreversible_reason
      relationships_redirected_count
      relationships_recreatable_count
      created_at
      unmerged_at
      proposal_id
      mergedBy {
        id
        name
      }
      unmergedBy {
        id
        name
      }
      target {
        id
        entity_type
        representative {
          main
        }
      }
      sources {
        id
        standard_id
        name
        entity_type
        aliases
        redirected_relationships_count
        recreatable_relationships_count
        contributed_aliases
        reverted_at
      }
      alias_provenance {
        alias
        source_id
        source_aliases
        relationships_count
      }
    }
  }
`;

const unmergeMutation = graphql`
  mutation MergeRecordDrawerUnmergeMutation($mergeRecordId: ID!, $sourceIds: [ID!]) {
    unmergeEntity(mergeRecordId: $mergeRecordId, sourceIds: $sourceIds) {
      id
      merge_status
      is_reversible
      unmerged_at
      unmergedBy {
        id
        name
      }
      sources {
        id
        reverted_at
      }
    }
  }
`;

const MergeRecordDetails = ({ recordId, onUnmerged }: { recordId: string; onUnmerged: () => void }) => {
  const theme = useTheme<Theme>();
  const { t_i18n, fldt, n } = useFormatter();
  const labels = useCurationLabels();
  const isGrantedToMerge = useGranted([KNOWLEDGE_KNUPDATE_KNMERGE]);
  const [selected, setSelected] = useState<string[]>([]);
  const [confirmOpen, setConfirmOpen] = useState(false);
  const { mergeRecord } = useLazyLoadQuery<MergeRecordDrawerQuery>(mergeRecordDrawerQuery, { id: recordId }, { fetchPolicy: 'store-and-network' });
  const [commitUnmerge, unmerging] = useApiMutation<MergeRecordDrawerUnmergeMutation>(unmergeMutation);
  if (!mergeRecord) {
    return <Typography variant="body2">{t_i18n('This merge record is not available')}</Typography>;
  }
  const restorable = mergeRecord.sources.filter((source) => !source.reverted_at);
  const canUnmerge = isGrantedToMerge && mergeRecord.is_reversible && restorable.length > 0;
  const toggle = (id: string) => setSelected((current) => (current.includes(id) ? current.filter((value) => value !== id) : [...current, id]));
  const targetLink = mergeRecord.target ? resolveLink(mergeRecord.target.entity_type) : null;
  const sourceNames = new Map(mergeRecord.sources.map((source) => [source.id, source.name]));
  const byAndDate = (name: string | null | undefined, date: string | null | undefined) => (name ? `${name} - ${fldt(date)}` : fldt(date));
  const comingBack = (selected.length > 0 ? restorable.filter((source) => selected.includes(source.id)) : restorable).map((source) => source.name);
  const sourceName = (sourceId: string) => {
    const name = sourceNames.get(sourceId);
    if (name) return name;
    return (
      <Tooltip>
        <TooltipTrigger asChild>
          <span>{t_i18n('Unknown source')}</span>
        </TooltipTrigger>
        <TooltipContent>{sourceId}</TooltipContent>
      </Tooltip>
    );
  };

  const unmerge = () => {
    commitUnmerge({
      variables: { mergeRecordId: mergeRecord.id, sourceIds: selected.length > 0 ? selected : null },
      onCompleted: (_, errors) => {
        if (notifyPayloadErrors(errors)) return;
        MESSAGING$.notifySuccess(t_i18n('The merged entities have been restored'));
        setConfirmOpen(false);
        setSelected([]);
        onUnmerged();
      },
    });
  };

  return (
    <Box sx={{ display: 'flex', flexDirection: 'column', gap: 3 }} data-testid="merge-record-details">
      <Box sx={{ display: 'flex', flexDirection: 'column', gap: 1 }} data-testid="merge-record-header">
        <Box sx={{ display: 'flex', alignItems: 'center', gap: 2, flexWrap: 'wrap' }}>
          <Tag
            label={labels.mergeStatus(mergeRecord.merge_status, mergeRecord.reversible_until)}
            color={labels.statusColor(mergeRecord.merge_status)}
          />
          <Box sx={{ display: 'flex', alignItems: 'center', gap: 1, flex: 1, minWidth: 0 }}>
            <ItemIcon type={mergeRecord.target?.entity_type ?? mergeRecord.merge_target_type} />
            <Typography variant="h3" sx={{ margin: 0 }}>
              {mergeRecord.target && targetLink
                ? <Link to={`${targetLink}/${mergeRecord.target.id}`}>{mergeRecord.target.representative.main}</Link>
                : mergeRecord.merge_target_name}
            </Typography>
          </Box>
          {canUnmerge && (
            <Button intent="destructive" onClick={() => setConfirmOpen(true)} disabled={unmerging} data-testid="merge-record-unmerge">
              {selected.length > 0 ? t_i18n('Undo the merge of the selected sources') : t_i18n('Undo the merge')}
            </Button>
          )}
        </Box>
        {!mergeRecord.is_reversible && mergeRecord.merge_status !== 'reverted' && (
          <Typography variant="caption" color={theme.palette.text.light} data-testid="merge-record-reversibility">
            {mergeRecord.irreversible_reason
              ? labels.irreversibility(mergeRecord.irreversible_reason, mergeRecord.reversible_until)
              : t_i18n('This merge could be undone until {date}.', { values: { date: fldt(mergeRecord.reversible_until) } })}
          </Typography>
        )}
      </Box>
      <Box sx={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 2 }}>
        <div>
          <Label>{t_i18n('Merged by')}</Label>
          <Typography variant="body2">{byAndDate(mergeRecord.mergedBy?.name, mergeRecord.created_at)}</Typography>
        </div>
        {!mergeRecord.irreversible_reason && (
          <div>
            <Label>{t_i18n('Reversible until')}</Label>
            <Typography variant="body2">{fldt(mergeRecord.reversible_until)}</Typography>
          </div>
        )}
        <div>
          <Label>{t_i18n('Relationships redirected')}</Label>
          <Typography variant="body2">{n(mergeRecord.relationships_redirected_count)}</Typography>
        </div>
        <div>
          <Label>{t_i18n('Relationships to recreate on unmerge')}</Label>
          <Typography variant="body2">{n(mergeRecord.relationships_recreatable_count)}</Typography>
        </div>
        {mergeRecord.unmerged_at && (
          <div>
            <Label>{t_i18n('Unmerge date')}</Label>
            <Typography variant="body2">{byAndDate(mergeRecord.unmergedBy?.name, mergeRecord.unmerged_at)}</Typography>
          </div>
        )}
        {mergeRecord.proposal_id && (
          <div>
            <Label>{t_i18n('Curation proposal')}</Label>
            <Link to={`${CURATION_PROPOSALS_PATH}/${mergeRecord.proposal_id}`}>{t_i18n('Open the proposal')}</Link>
          </div>
        )}
      </Box>
      <div>
        <Label>{t_i18n('Merged sources')}</Label>
        <Table size="small" aria-label={t_i18n('Merged sources')}>
          <TableHead>
            <TableRow>
              {canUnmerge && <TableCell sx={{ width: 48 }} />}
              <TableCell>{t_i18n('Name')}</TableCell>
              <TableCell>{t_i18n('Aliases')}</TableCell>
              <TableCell>{t_i18n('Relationships')}</TableCell>
              <TableCell>{t_i18n('Status')}</TableCell>
            </TableRow>
          </TableHead>
          <TableBody>
            {mergeRecord.sources.map((source) => (
              <TableRow key={source.id}>
                {canUnmerge && (
                  <TableCell>
                    {!source.reverted_at && (
                      <Checkbox
                        aria-label={t_i18n('Restore {name}', { values: { name: source.name } })}
                        checked={selected.includes(source.id)}
                        onCheckedChange={() => toggle(source.id)}
                      />
                    )}
                  </TableCell>
                )}
                <TableCell>{source.name}</TableCell>
                <TableCell>
                  <Box sx={{ display: 'flex', flexWrap: 'wrap', gap: 0.5 }}>
                    {source.aliases.slice(0, 10).map((alias) => <Tag key={alias} label={alias} labelTextTransform="none" />)}
                  </Box>
                </TableCell>
                <TableCell>{n(source.redirected_relationships_count + source.recreatable_relationships_count)}</TableCell>
                <TableCell>{source.reverted_at ? t_i18n('Restored on {date}', { values: { date: fldt(source.reverted_at) } }) : t_i18n('Merged')}</TableCell>
              </TableRow>
            ))}
          </TableBody>
        </Table>
      </div>
      {mergeRecord.alias_provenance.length > 0 && (
        <div>
          <Label>{t_i18n('Alias provenance')}</Label>
          <Table size="small" aria-label={t_i18n('Alias provenance')}>
            <TableHead>
              <TableRow>
                <TableCell>{t_i18n('Alias')}</TableCell>
                <TableCell>{t_i18n('Brought by')}</TableCell>
                <TableCell>{t_i18n('Relationships')}</TableCell>
              </TableRow>
            </TableHead>
            <TableBody>
              {mergeRecord.alias_provenance.map((provenance) => (
                <TableRow key={`${provenance.source_id}-${provenance.alias}`}>
                  <TableCell>{provenance.alias}</TableCell>
                  <TableCell>{sourceName(provenance.source_id)}</TableCell>
                  <TableCell>{n(provenance.relationships_count)}</TableCell>
                </TableRow>
              ))}
            </TableBody>
          </Table>
        </div>
      )}
      {!isGrantedToMerge && mergeRecord.is_reversible && (
        <Typography variant="body2" color={theme.palette.text.light}>
          {t_i18n('Undoing a merge requires the capability to merge knowledge')}
        </Typography>
      )}
      <Dialog open={confirmOpen} onClose={() => setConfirmOpen(false)} title={t_i18n('Undo the merge')}>
        <Typography variant="body2" sx={{ marginBottom: 1 }} data-testid="merge-record-unmerge-preview">
          {t_i18n('{count, plural, one {# entity comes back: {names}.} other {# entities come back: {names}.}}', {
            values: { count: comingBack.length, names: comingBack.join(', ') },
          })}
        </Typography>
        <Typography variant="body2">
          {t_i18n('Each one gets back its identifiers, aliases and relationships, and the relationships it brought move back to it.')}
        </Typography>
        <DialogActions>
          <Button variant="secondary" onClick={() => setConfirmOpen(false)} disabled={unmerging}>
            {t_i18n('Cancel')}
          </Button>
          <Button intent="destructive" onClick={unmerge} disabled={unmerging} data-testid="merge-record-unmerge-confirm">
            {t_i18n('Undo the merge')}
          </Button>
        </DialogActions>
      </Dialog>
    </Box>
  );
};

interface MergeRecordDrawerProps {
  recordId: string | null;
  onClose: () => void;
  onUnmerged: () => void;
}

const MergeRecordDrawer = ({ recordId, onClose, onUnmerged }: MergeRecordDrawerProps) => {
  const { t_i18n } = useFormatter();
  return (
    <Drawer title={t_i18n('Merge record')} open={!!recordId} onClose={onClose} size="large">
      {recordId ? (
        <Suspense fallback={<CurationSkeleton blocks={[40, 160, 200]} />}>
          <MergeRecordDetails recordId={recordId} onUnmerged={onUnmerged} />
        </Suspense>
      ) : null}
    </Drawer>
  );
};

export default MergeRecordDrawer;
