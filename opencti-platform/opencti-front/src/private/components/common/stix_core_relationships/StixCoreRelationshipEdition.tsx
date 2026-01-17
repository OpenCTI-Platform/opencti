import { StixCoreRelationshipEditionOverviewQuery } from '@components/common/stix_core_relationships/__generated__/StixCoreRelationshipEditionOverviewQuery.graphql';
import React from 'react';
import { graphql, PreloadedQuery, usePreloadedQuery } from 'react-relay';
import { useFormatter } from '../../../../components/i18n';
import Loader, { LoaderVariant } from '../../../../components/Loader';
import useQueryLoading from '../../../../utils/hooks/useQueryLoading';
import Drawer from '../drawer/Drawer';
import StixCoreRelationshipEditionOverview, { stixCoreRelationshipEditionOverviewQuery } from './StixCoreRelationshipEditionOverview';
import { StixCoreRelationshipEditionContextQuery } from './__generated__/StixCoreRelationshipEditionContextQuery.graphql';

export const stixCoreRelationshipEditionDeleteMutation = graphql`
  mutation StixCoreRelationshipEditionDeleteMutation($id: ID!) {
    stixCoreRelationshipEdit(id: $id) {
      delete
    }
  }
`;

const stixCoreRelationshipEditionContextQuery = graphql`
  query StixCoreRelationshipEditionContextQuery($id: String!) {
    stixCoreRelationship(id: $id) {
      editContext {
        name
        focusOn
      }
    }
  }
`;

type StixCoreRelationshipEditionContainerProps = {
  stixCoreRelationshipId: string;
  open: boolean;
  noStoreUpdate: boolean;
  handleDelete?: () => void;
  handleClose: () => void;
  isCoverage?: boolean;
};

const StixCoreRelationshipEditionContainer = (props: StixCoreRelationshipEditionContainerProps) => {
  const {
    stixCoreRelationshipId,
  } = props;

  const contextQueryRef = useQueryLoading<StixCoreRelationshipEditionContextQuery>(
    stixCoreRelationshipEditionContextQuery,
    { id: stixCoreRelationshipId },
  );

  if (!contextQueryRef) return null;

  return (
    <StixCoreRelationshipEditionContainerContent
      {...props}
      contextQueryRef={contextQueryRef}
    />
  );
};

const StixCoreRelationshipEditionContainerContent = ({
  open,
  stixCoreRelationshipId,
  handleClose,
  handleDelete,
  noStoreUpdate,
  isCoverage = false,
  contextQueryRef,
}: StixCoreRelationshipEditionContainerProps & {
  contextQueryRef: PreloadedQuery<StixCoreRelationshipEditionContextQuery>;
}) => {
  const { t_i18n } = useFormatter();

  const contextData = usePreloadedQuery(
    stixCoreRelationshipEditionContextQuery,
    contextQueryRef,
  );

  const editContext = contextData?.stixCoreRelationship?.editContext;

  const queryRef = useQueryLoading<StixCoreRelationshipEditionOverviewQuery>(
    stixCoreRelationshipEditionOverviewQuery,
    { id: stixCoreRelationshipId },
  );

  return (
    <Drawer
      open={open}
      onClose={handleClose}
      title={t_i18n('Update a relationship')}
      context={editContext}
    >
      {queryRef ? (
        <React.Suspense fallback={<Loader variant={LoaderVariant.inline} />}>
          <StixCoreRelationshipEditionOverview
            queryRef={queryRef}
            handleClose={handleClose}
            handleDelete={handleDelete}
            noStoreUpdate={noStoreUpdate}
            isCoverage={isCoverage}
          />
        </React.Suspense>
      ) : (
        <Loader variant={LoaderVariant.inline} />
      )}
    </Drawer>
  );
};

export default StixCoreRelationshipEditionContainer;
