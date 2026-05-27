import React, { FunctionComponent, Suspense, useMemo } from 'react';
import { graphql, PreloadedQuery, usePreloadedQuery } from 'react-relay';
import Typography from '@mui/material/Typography';
import Box from '@mui/material/Box';
import { useFormatter } from '../../../../components/i18n';
import { Change } from '../../../../components/common/table/ChangesTable';
import { DraftReviewResolvedChangesQuery } from './__generated__/DraftReviewResolvedChangesQuery.graphql';
import { formatFieldKey, isResolvableId, RenderChangeValuesFn } from './draftReviewDiffPanelUtils';
import useQueryLoading from '../../../../utils/hooks/useQueryLoading';
import Loader from '../../../../components/Loader';

const draftReviewResolvedChangesQuery = graphql`
  query DraftReviewResolvedChangesQuery($draftId: String!, $ids: [String!]!) {
    draftWorkspaceResolveIds(draftId: $draftId, ids: $ids) {
      id
      representative_main
    }
  }
`;

interface DraftReviewResolvedChangesComponentProps {
  queryRef: PreloadedQuery<DraftReviewResolvedChangesQuery>;
  changes: Change[];
  labelMap: Record<string, string>;
  renderChangeValues: RenderChangeValuesFn;
}

const DraftReviewResolvedChangesComponent: FunctionComponent<DraftReviewResolvedChangesComponentProps> = ({
  queryRef,
  changes,
  labelMap,
  renderChangeValues,
}) => {
  const { t_i18n } = useFormatter();

  const resolvedData = usePreloadedQuery<DraftReviewResolvedChangesQuery>(
    draftReviewResolvedChangesQuery,
    queryRef,
  );

  const idLabelMap = useMemo(() => {
    const map: Record<string, string> = {};
    for (const item of resolvedData.draftWorkspaceResolveIds ?? []) {
      if (item.representative_main) map[item.id] = item.representative_main;
    }
    return map;
  }, [resolvedData]);

  return (
    <Box sx={{ display: 'flex', flexDirection: 'column', gap: '8px' }}>
      {changes.map((row) => (
        <Box key={row.field} sx={{ backgroundColor: 'background.paper', borderRadius: '4px', p: '8px 16px', display: 'flex', flexDirection: 'column', gap: '8px' }}>
          <Typography sx={{ color: 'text.secondary', fontWeight: 500, fontSize: 12, letterSpacing: '0.0075em' }}>
            {formatFieldKey(row.field, labelMap, t_i18n)}
          </Typography>
          <Box sx={{ display: 'flex', flexDirection: 'row', gap: '16px' }}>
            <Box sx={{ flex: 1, fontSize: 14, letterSpacing: '0.0075em' }}>
              {renderChangeValues(row.removed, true, idLabelMap)}
            </Box>
            <Box sx={{ flex: 1, fontSize: 14, letterSpacing: '0.0075em' }}>
              {renderChangeValues(row.added, false, idLabelMap)}
            </Box>
          </Box>
        </Box>
      ))}
    </Box>
  );
};

interface DraftReviewResolvedChangesProps {
  draftId: string;
  changes: Change[];
  labelMap: Record<string, string>;
  renderChangeValues: RenderChangeValuesFn;
}

const DraftReviewResolvedChanges: FunctionComponent<DraftReviewResolvedChangesProps> = ({
  draftId,
  changes,
  labelMap,
  renderChangeValues,
}) => {
  const stixIds = useMemo(() => {
    return Array.from(new Set(
      changes.flatMap((c) => [...(c.added ?? []), ...(c.removed ?? [])]).filter(isResolvableId),
    ));
  }, [changes]);
  const queryRef = useQueryLoading<DraftReviewResolvedChangesQuery>(
    draftReviewResolvedChangesQuery,
    { draftId, ids: stixIds },
  );
  return (
    <Suspense fallback={<Loader />}>
      {queryRef && (
        <DraftReviewResolvedChangesComponent
          queryRef={queryRef}
          changes={changes}
          labelMap={labelMap}
          renderChangeValues={renderChangeValues}
        />
      )}
    </Suspense>
  );
};

export default DraftReviewResolvedChanges;
