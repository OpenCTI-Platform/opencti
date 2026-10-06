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
  // The chip owns a tooltip for clipped labels, and the opening of any tooltip closes the others: this one follows
  // the pointer and the focus of the chip itself
  const [breakdownOpen, setBreakdownOpen] = useState(false);

  useEffect(() => {
    // The server debounces the writes, the overview records the visit once per opening. The request is never
    // cancelled, so a brief visit is recorded too: leaving the overview only ignores the answer
    let active = true;
    // The overview can be reused for another entity: its chip never shows the counters of the previous one
    setData(null);
    commit({
      variables: { id: entityId },
      onCompleted: (response) => {
        if (active) setData(response.entityVisitRecord ?? null);
      },
      onError: () => {
        if (active) setData(null);
      },
    });
    return () => {
      active = false;
    };
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
      <Tooltip open={breakdownOpen}>
        <TooltipTrigger asChild>
          <span
            onPointerEnter={() => setBreakdownOpen(true)}
            onPointerLeave={() => setBreakdownOpen(false)}
            onFocus={() => setBreakdownOpen(true)}
            onBlur={() => setBreakdownOpen(false)}
            onKeyDown={(event) => {
              if (event.key === 'Escape') setBreakdownOpen(false);
            }}
          >
            <Chip
              label={label}
              severity={hasChanges ? 'info' : 'neutral'}
              onClick={openChanges}
              aria-label={openChanges ? t_i18n('{label}, open the changes since {date}', { values: { label, date: fldt(referenceDate) } }) : undefined}
            />
          </span>
        </TooltipTrigger>
        <TooltipContent onEscapeKeyDown={() => setBreakdownOpen(false)}>
          <Box component="span" sx={{ display: 'flex', flexDirection: 'column' }} data-testid="since-last-visit-breakdown">
            {hasChanges && <span>{t_i18n('By other users')}</span>}
            {breakdown.map((line) => <span key={line}>{line}</span>)}
            <span>{lastVisit}</span>
          </Box>
        </TooltipContent>
      </Tooltip>
    </Box>
  );
};

export default SinceLastVisitChips;
