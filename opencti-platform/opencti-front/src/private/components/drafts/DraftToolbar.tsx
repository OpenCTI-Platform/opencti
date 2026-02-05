import { Suspense } from 'react';
import { useTheme } from '@mui/styles';
import { graphql } from 'relay-runtime';
import { PreloadedQuery, useFragment, usePreloadedQuery } from 'react-relay';
import { Stack, Tooltip, Typography } from '@mui/material';
import useDraftContext from '../../../utils/hooks/useDraftContext';
import { Theme } from '../../../components/Theme';
import DraftProcessingStatus from './DraftProcessingStatus';
import { useQueryLoadingWithLoadQuery } from '../../../utils/hooks/useQueryLoading';
import { DraftToolbarQuery } from './__generated__/DraftToolbarQuery.graphql';
import ErrorNotFound from '../../../components/ErrorNotFound';
import { DraftToolbarFragment$key } from './__generated__/DraftToolbarFragment.graphql';
import { useGetCurrentUserAccessRight } from '../../../utils/authorizedMembers';
import Security from '../../../utils/Security';
import { useFormatter } from '../../../components/i18n';
import IconButton from '../../../components/common/button/IconButton';
import { LockOutlined } from '@mui/icons-material';
import { KNOWLEDGE_KNUPDATE_KNMANAGEAUTHMEMBERS } from '../../../utils/hooks/useGranted';
import DraftApprove from './DraftApprove';
import DraftExit from './DraftExit';
import { THIRTY_SECONDS } from '../../../utils/Time';
import useInterval from '../../../utils/hooks/useInterval';

const draftFragment = graphql`
  fragment DraftToolbarFragment on DraftWorkspace {
    ...DraftApproveFragment
    ...DraftExitFragment
    id
    name
    entity_id
    draft_status
    processingCount
    objectsCount {
      totalCount
    }
    currentUserAccessRight
    authorizedMembers {
      id
      name
      entity_type
      access_right
      member_id
      groups_restriction {
        id
        name
      }
    }
    creators {
      id
      name
      entity_type
    }
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
  const { t_i18n } = useFormatter();

  const { draftWorkspace } = usePreloadedQuery(draftQuery, queryRef);
  if (!draftWorkspace) return (<ErrorNotFound />);

  const draft = useFragment<DraftToolbarFragment$key>(draftFragment, draftWorkspace);
  const {
    name,
    currentUserAccessRight,
  } = draft;

  const currentAccessRight = useGetCurrentUserAccessRight(currentUserAccessRight);

  return (
    <Stack
      sx={{
        p: 2,
        gap: 1,
        alignItems: 'center',
        flexDirection: 'row',
        background: theme.palette.designSystem.background.bg4,
        borderTop: `1px solid ${theme.palette.designSystem.alert.warning.primary}`,
      }}
    >
      <Typography variant="h6">{name}</Typography>
      <DraftProcessingStatus forceRefetch={refetch} />

      <div style={{ flex: 1 }} />

      {currentAccessRight.canManage && (
        <Security needs={[KNOWLEDGE_KNUPDATE_KNMANAGEAUTHMEMBERS]}>
          <Tooltip title={t_i18n('Authorized members')}>
            <IconButton
              size="default"
              onClick={() => {}}
              variant="secondary"
            >
              <LockOutlined fontSize="small" />
            </IconButton>
          </Tooltip>
        </Security>
      )}

      <DraftExit data={draft} />
      <DraftApprove data={draft} />
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
    () => loadQuery({ id: draftId }),
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
