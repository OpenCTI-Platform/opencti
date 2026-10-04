import React, { useEffect, useState } from 'react';
import { graphql, useMutation } from 'react-relay';
import { useNavigate } from 'react-router';
import { Chip, Tooltip, TooltipContent, TooltipTrigger } from '@filigran/design-system';
import { Box } from '@mui/material';
import { useFormatter } from '../../../../components/i18n';
import { countLabel, sinceLastVisitSearch } from './timeMachineUtils';
import { SinceLastVisitChipsRecordMutation, SinceLastVisitChipsRecordMutation$data } from './__generated__/SinceLastVisitChipsRecordMutation.graphql';

const sinceLastVisitChipsRecordMutation = graphql`
  mutation SinceLastVisitChipsRecordMutation($id: String!) {
    entityVisitRecord(id: $id) {
      entity_id
      first_visit
      reference_date
      last_seen_at
      new_relationships
      updates
      new_container_objects
    }
  }
`;

type SinceLastVisitData = NonNullable<SinceLastVisitChipsRecordMutation$data['entityVisitRecord']>;

interface SinceLastVisitChipsProps {
  entityId: string;
  // Path of the Changes tab of the entity, when it has one
  changesPath?: string;
}

/**
 * Records the visit of the user on the entity overview and displays one chip for what changed since the
 * previous visit; its tooltip breaks the changes down (new relationships, updates by others, objects added
 * to a container) and a click opens the comparison since that visit in the Changes tab.
 */
const SinceLastVisitChips = ({ entityId, changesPath }: SinceLastVisitChipsProps) => {
  const { t_i18n, rd, fldt } = useFormatter();
  const navigate = useNavigate();
  const [commit] = useMutation<SinceLastVisitChipsRecordMutation>(sinceLastVisitChipsRecordMutation);
  const [data, setData] = useState<SinceLastVisitData | null>(null);

  useEffect(() => {
    // The server debounces the writes, the overview records the visit once per opening
    const disposable = commit({
      variables: { id: entityId },
      onCompleted: (response) => setData(response.entityVisitRecord ?? null),
      onError: () => setData(null),
    });
    return () => disposable.dispose();
  }, [entityId]);

  if (!data || data.first_visit || !data.reference_date) {
    return null;
  }
  const referenceDate = data.reference_date;
  const breakdown = [
    data.new_relationships > 0 ? countLabel('new_relationships', data.new_relationships, t_i18n) : null,
    data.updates > 0 ? countLabel('updates', data.updates, t_i18n) : null,
    data.new_container_objects > 0 ? countLabel('new_container_objects', data.new_container_objects, t_i18n) : null,
  ].filter((line): line is string => !!line);
  const hasChanges = breakdown.length > 0;
  const lastVisit = t_i18n('Last visit {date}', { values: { date: rd(referenceDate) } });
  const label = hasChanges ? t_i18n('New since your last visit') : t_i18n('No change since your last visit');
  const openChanges = changesPath && hasChanges ? () => navigate(`${changesPath}?${sinceLastVisitSearch(referenceDate)}`) : undefined;
  return (
    <Box sx={{ display: 'flex', alignItems: 'center', marginBottom: 2 }} data-testid="since-last-visit" role="status">
      <Tooltip>
        <TooltipTrigger asChild>
          <span>
            <Chip
              label={label}
              severity={hasChanges ? 'info' : 'neutral'}
              onClick={openChanges}
              aria-label={openChanges ? t_i18n('{label}, open the changes since {date}', { values: { label, date: fldt(referenceDate) } }) : undefined}
            />
          </span>
        </TooltipTrigger>
        <TooltipContent>
          <Box component="span" sx={{ display: 'flex', flexDirection: 'column' }} data-testid="since-last-visit-breakdown">
            {breakdown.map((line) => <span key={line}>{line}</span>)}
            <span>{lastVisit}</span>
          </Box>
        </TooltipContent>
      </Tooltip>
    </Box>
  );
};

export default SinceLastVisitChips;
