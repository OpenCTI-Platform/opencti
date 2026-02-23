import { Suspense } from 'react';
import { useTheme } from '@mui/styles';
import { graphql } from 'relay-runtime';
import { PreloadedQuery, useFragment, usePreloadedQuery } from 'react-relay';
import { Stack, Typography } from '@mui/material';
import useDraftContext from '../../../utils/hooks/useDraftContext';
import { Theme } from '../../../components/Theme';
import DraftProcessingStatus from './DraftProcessingStatus';
import { useQueryLoadingWithLoadQuery } from '../../../utils/hooks/useQueryLoading';
import ErrorNotFound from '../../../components/ErrorNotFound';
import DraftExit from './DraftExit';
import { THIRTY_SECONDS } from '../../../utils/Time';
import useInterval from '../../../utils/hooks/useInterval';
import DraftAuthorizedMembers from './DraftAuthorizedMembers';
import WorkflowStatus, { WorkflowTransitions } from '../common/workflow/WorkflowStatus';
import { DraftToolbarQuery } from '@components/drafts/__generated__/DraftToolbarQuery.graphql';
import { DraftToolbarFragment$key } from '@components/drafts/__generated__/DraftToolbarFragment.graphql';

const draftFragment = graphql`
  fragment DraftToolbarFragment on DraftWorkspace {
    name
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
  refetch: () => void;
}

const DraftToolbarComponent = ({
  queryRef,
  refetch,
}: DraftToolbarComponentProps) => {
  const theme = useTheme<Theme>();

  const { draftWorkspace } = usePreloadedQuery(draftQuery, queryRef);
  if (!draftWorkspace) return (<ErrorNotFound />);

  const draft = useFragment<DraftToolbarFragment$key>(draftFragment, draftWorkspace);

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
      <DraftProcessingStatus forceRefetch={refetch} />

      <div style={{ flex: 1 }} />

      <WorkflowStatus data={draft} />
      <WorkflowTransitions data={draft} />
      <DraftAuthorizedMembers data={draft} />
      <DraftExit data={draft} />
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

  useInterval(
    () => {
      loadQuery(
        { id: draftId },
        { fetchPolicy: 'store-and-network' },
      );
    },
    THIRTY_SECONDS,
  );

  return queryRef && (
    <Suspense>
      <DraftToolbarComponent
        queryRef={queryRef}
        refetch={() => loadQuery({ id: draftId })}
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
