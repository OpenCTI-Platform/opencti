import { Suspense } from 'react';
import { useTheme } from '@mui/styles';
import { graphql } from 'relay-runtime';
import { PreloadedQuery, useFragment, usePreloadedQuery } from 'react-relay';
import { Stack, Typography } from '@mui/material';
import useDraftContext from '../../../utils/hooks/useDraftContext';
import { Theme } from '../../../components/Theme';
import DraftProcessingStatus from './DraftProcessingStatus';
import { useQueryLoadingWithLoadQuery } from '../../../utils/hooks/useQueryLoading';
import type { LoadQueryOptions } from 'react-relay';
import ErrorNotFound from '../../../components/ErrorNotFound';
import DraftExit from './DraftExit';
import { FIVE_SECONDS, THIRTY_SECONDS } from '../../../utils/Time';
import useInterval from '../../../utils/hooks/useInterval';
import DraftAuthorizedMembers from './DraftAuthorizedMembers';
import WorkflowStatus, { WorkflowTransitions } from '../common/workflow/WorkflowStatus';
import { DraftToolbarQuery } from '@components/drafts/__generated__/DraftToolbarQuery.graphql';
import { DraftToolbarFragment$key } from '@components/drafts/__generated__/DraftToolbarFragment.graphql';

const draftFragment = graphql`
  fragment DraftToolbarFragment on DraftWorkspace {
    name
    workflowInstance {
      pendingStatus
    }
    ...DraftExitFragment
    ...DraftAuthorizedMembersFragment
    ...WorkflowStatus_data
  }
`;

const draftQuery = graphql`
  query DraftToolbarQuery($id: String!) {
    draftWorkspace(id: $id) {
      ...DraftToolbarFragment
    }
  }
`;

interface DraftToolbarComponentProps {
  queryRef: PreloadedQuery<DraftToolbarQuery>;
  loadQuery: (variables: { id: string }, options?: LoadQueryOptions) => void;
  draftId: string;
}

const DraftToolbarComponent = ({
  queryRef,
  loadQuery,
  draftId,
}: DraftToolbarComponentProps) => {
  const theme = useTheme<Theme>();

  const { draftWorkspace } = usePreloadedQuery(draftQuery, queryRef);
  if (!draftWorkspace) return (<ErrorNotFound />);

  const draft = useFragment<DraftToolbarFragment$key>(draftFragment, draftWorkspace);

  const isPending = draft.workflowInstance?.pendingStatus === 'pending';
  useInterval(
    () => {
      loadQuery({ id: draftId }, { fetchPolicy: 'store-and-network' });
    },
    isPending ? FIVE_SECONDS : THIRTY_SECONDS,
  );

  return (
    <Stack
      sx={{
        p: 2,
        gap: 1,
        alignItems: 'center',
        flexDirection: 'row',
        background: theme.palette.designSystem.background.bg4,
        borderTop: `1px solid ${theme.palette.designSystem.alert.warning.primary}`,
        zIndex: theme.zIndex.appBar + 1,
      }}
    >
      <Typography
        variant="h6"
        sx={{ textTransform: 'none' }}
      >
        {draft.name}
      </Typography>
      <DraftProcessingStatus forceRefetch={() => loadQuery({ id: draftId })} />

      <div style={{ flex: 1 }} />

      <WorkflowStatus data={draft} />
      <DraftAuthorizedMembers data={draft} />
      <DraftExit data={draft} />
      <WorkflowTransitions data={draft} />
    </Stack>
  );
};

interface DraftToolbarWrapperProps {
  draftId: string;
}

const DraftToolbarWrapper = ({ draftId }: DraftToolbarWrapperProps) => {
  const [queryRef, loadQuery] = useQueryLoadingWithLoadQuery<DraftToolbarQuery>(
    draftQuery,
    { id: draftId },
  );

  return queryRef && (
    <Suspense>
      <DraftToolbarComponent
        queryRef={queryRef}
        loadQuery={loadQuery}
        draftId={draftId}
      />
    </Suspense>
  );
};

const DraftToolbar = () => {
  const draftContext = useDraftContext();
  if (!draftContext) return null;
  return <DraftToolbarWrapper draftId={draftContext.id} />;
};

export default DraftToolbar;
