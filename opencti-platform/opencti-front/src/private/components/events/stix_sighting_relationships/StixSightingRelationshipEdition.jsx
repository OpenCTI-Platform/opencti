import React from 'react';
import { graphql, usePreloadedQuery } from 'react-relay';
import StixSightingRelationshipEditionOverview, { stixSightingRelationshipEditionOverviewQuery } from './StixSightingRelationshipEditionOverview';
import Loader, { LoaderVariant } from '../../../../components/Loader';
import useQueryLoading from '../../../../utils/hooks/useQueryLoading';
import Drawer from '@components/common/drawer/Drawer';
import { useFormatter } from '../../../../components/i18n';

export const stixSightingRelationshipEditionDeleteMutation = graphql`
  mutation StixSightingRelationshipEditionDeleteMutation($id: ID!) {
    stixSightingRelationshipEdit(id: $id) {
      delete
    }
  }
`;

const stixSightingRelationshipEditContextQuery = graphql`
  query StixSightingRelationshipEditionEditContextQuery($id: String!) {
    stixSightingRelationship(id: $id) {
      id
      editContext {
        name
        focusOn
      }
    }
  }
`;

const StixSightingRelationshipEditionWithContext = ({
  stixSightingRelationshipId,
  open,
  handleClose,
  inferred,
  noStoreUpdate,
  inGraph,
}) => {
  const editContextQueryRef = useQueryLoading(stixSightingRelationshipEditContextQuery, { id: stixSightingRelationshipId });

  if (!editContextQueryRef) {
    return null;
  }

  return (
    <React.Suspense>
      <StixSightingRelationshipEditionWithContextContent
        editContextQueryRef={editContextQueryRef}
        stixSightingRelationshipId={stixSightingRelationshipId}
        open={open}
        handleClose={handleClose}
        inferred={inferred}
        noStoreUpdate={noStoreUpdate}
        inGraph={inGraph}
      />
    </React.Suspense>
  );
};

const StixSightingRelationshipEditionWithContextContent = ({
  editContextQueryRef,
  stixSightingRelationshipId,
  open,
  handleClose,
  inferred,
  noStoreUpdate,
  inGraph,
}) => {
  const data = usePreloadedQuery(stixSightingRelationshipEditContextQuery, editContextQueryRef);
  const editContext = data.stixSightingRelationship?.editContext;

  return (
    <StixSightingRelationshipEdition
      stixSightingRelationshipId={stixSightingRelationshipId}
      open={open}
      handleClose={handleClose}
      inferred={inferred}
      noStoreUpdate={noStoreUpdate}
      inGraph={inGraph}
      editContext={editContext}
    />
  );
};

const StixSightingRelationshipEdition = ({
  stixSightingRelationshipId,
  open,
  handleClose,
  inferred,
  noStoreUpdate,
  inGraph,
  editContext,
}) => {
  const { t_i18n } = useFormatter();
  const queryRef = useQueryLoading(stixSightingRelationshipEditionOverviewQuery, { id: stixSightingRelationshipId });

  const renderInGraph = () => {
    return (
      <Drawer
        title={t_i18n('Update a sighting')}
        context={editContext}
        open={open}
        onClose={handleClose}
      >
        {queryRef ? (
          <React.Suspense fallback={<Loader variant={LoaderVariant.inline} />}>
            <StixSightingRelationshipEditionOverview
              queryRef={queryRef}
              handleClose={handleClose}
              inferred={inferred}
              noStoreUpdate={noStoreUpdate}
            />
          </React.Suspense>
        ) : (
          <Loader variant={LoaderVariant.inline} />
        )}
      </Drawer>
    );
  };

  const renderClassic = () => {
    return (
      <Drawer
        title={t_i18n('Update a sighting')}
        context={editContext}
        open={open}
        onClose={handleClose}
      >
        {queryRef ? (
          <React.Suspense fallback={<Loader variant={LoaderVariant.inline} />}>
            <StixSightingRelationshipEditionOverview
              queryRef={queryRef}
              handleClose={handleClose}
              inferred={inferred}
              noStoreUpdate={noStoreUpdate}
            />
          </React.Suspense>
        ) : (
          <Loader variant={LoaderVariant.inline} />
        )}
      </Drawer>
    );
  };

  if (inGraph) {
    // in a graph bar
    return renderInGraph();
  }
  return renderClassic();
};

export default StixSightingRelationshipEditionWithContext;
