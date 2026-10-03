import React, { useEffect, useState } from 'react';
import { graphql, useMutation } from 'react-relay';
import { Chip, Tooltip, TooltipContent, TooltipTrigger } from '@filigran/design-system';
import { Box } from '@mui/material';
import { useFormatter } from '../../../../components/i18n';
import { countLabel } from './timeMachineUtils';
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
}

/**
 * Records the visit of the user on the entity overview and displays what changed since the
 * previous visit (new relationships, updates by others, objects added to a container).
 */
const SinceLastVisitChips = ({ entityId }: SinceLastVisitChipsProps) => {
  const { t_i18n, fldt } = useFormatter();
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
  const hasChanges = data.new_relationships > 0 || data.updates > 0 || data.new_container_objects > 0;
  const since = fldt(data.reference_date);
  return (
    <Box
      sx={{ display: 'flex', alignItems: 'center', gap: 1, flexWrap: 'wrap', marginBottom: 2 }}
      data-testid="since-last-visit"
      role="status"
      aria-label={t_i18n('New since your last visit')}
    >
      <Tooltip>
        <TooltipTrigger asChild>
          <span>
            <Chip label={hasChanges ? t_i18n('New since your last visit') : t_i18n('No change since your last visit')} severity={hasChanges ? 'info' : 'neutral'} />
          </span>
        </TooltipTrigger>
        <TooltipContent>{`${t_i18n('Last visit')}: ${since}`}</TooltipContent>
      </Tooltip>
      {data.new_relationships > 0 && (
        <Chip label={countLabel('new_relationships', data.new_relationships, t_i18n)} severity="info" />
      )}
      {data.updates > 0 && (
        <Chip label={countLabel('updates', data.updates, t_i18n)} severity="info" />
      )}
      {data.new_container_objects > 0 && (
        <Chip label={countLabel('new_container_objects', data.new_container_objects, t_i18n)} severity="info" />
      )}
    </Box>
  );
};

export default SinceLastVisitChips;
