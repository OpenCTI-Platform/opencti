import React, { FunctionComponent, Suspense } from 'react';
import { graphql, PreloadedQuery, usePreloadedQuery } from 'react-relay';
import { Change } from '../../../../components/common/table/ChangesTable';
import { DraftReviewEntityFieldsQuery } from './__generated__/DraftReviewEntityFieldsQuery.graphql';
import { EXCLUDED_PATCH_FIELDS, RenderChangeValuesFn } from './draftReviewDiffPanelUtils';
import DraftReviewResolvedChanges from './DraftReviewResolvedChanges';
import useQueryLoading from '../../../../utils/hooks/useQueryLoading';
import Loader from '../../../../components/Loader';

const draftReviewEntityFieldsQuery = graphql`
  query DraftReviewEntityFieldsQuery($draftId: String!, $entityId: String!) {
    draftWorkspaceEntityFields(draftId: $draftId, entityId: $entityId) {
      field
      values
    }
  }
`;

interface DraftReviewEntityFieldsComponentProps {
  queryRef: PreloadedQuery<DraftReviewEntityFieldsQuery>;
  draftId: string;
  mode: 'create' | 'delete';
  labelMap: Record<string, string>;
  renderChangeValues: RenderChangeValuesFn;
}

const DraftReviewEntityFieldsComponent: FunctionComponent<DraftReviewEntityFieldsComponentProps> = ({
  queryRef,
  draftId,
  mode,
  labelMap,
  renderChangeValues,
}) => {
  const fieldsData = usePreloadedQuery<DraftReviewEntityFieldsQuery>(
    draftReviewEntityFieldsQuery,
    queryRef,
  );

  const rawFields: ReadonlyArray<{ field: string; values: ReadonlyArray<string> }> = fieldsData.draftWorkspaceEntityFields ?? [];
  const changes: Change[] = rawFields
    .filter(({ field }) => !EXCLUDED_PATCH_FIELDS.has(field))
    .map(({ field, values }) => ({
      field,
      removed: mode === 'delete' ? [...values] : [],
      added: mode === 'create' ? [...values] : [],
    }));

  if (changes.length === 0) {
    return null;
  }

  return (
    <DraftReviewResolvedChanges
      draftId={draftId}
      changes={changes}
      labelMap={labelMap}
      renderChangeValues={renderChangeValues}
    />
  );
};

interface DraftReviewEntityFieldsProps {
  draftId: string;
  entityId: string;
  mode: 'create' | 'delete';
  labelMap: Record<string, string>;
  renderChangeValues: RenderChangeValuesFn;
}

const DraftReviewEntityFields: FunctionComponent<DraftReviewEntityFieldsProps> = ({
  draftId,
  entityId,
  mode,
  labelMap,
  renderChangeValues,
}) => {
  const queryRef = useQueryLoading<DraftReviewEntityFieldsQuery>(
    draftReviewEntityFieldsQuery,
    { draftId, entityId },
  );
  return (
    <Suspense fallback={<Loader />}>
      {queryRef && (
        <DraftReviewEntityFieldsComponent
          queryRef={queryRef}
          draftId={draftId}
          mode={mode}
          labelMap={labelMap}
          renderChangeValues={renderChangeValues}
        />
      )}
    </Suspense>
  );
};

export default DraftReviewEntityFields;
