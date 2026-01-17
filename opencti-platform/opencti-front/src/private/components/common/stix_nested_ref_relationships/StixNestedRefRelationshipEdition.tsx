import React, { FunctionComponent } from 'react';
import {
  StixNestedRefRelationshipEditionOverviewQuery,
} from '@components/common/stix_nested_ref_relationships/__generated__/StixNestedRefRelationshipEditionOverviewQuery.graphql';
import { graphql, PreloadedQuery, usePreloadedQuery } from 'react-relay';
import { useFormatter } from '../../../../components/i18n';
import Loader, { LoaderVariant } from '../../../../components/Loader';
import useQueryLoading from '../../../../utils/hooks/useQueryLoading';
import Drawer from '../drawer/Drawer';
import { StixNestedRefRelationshipEditionContextQuery } from './__generated__/StixNestedRefRelationshipEditionContextQuery.graphql';
import StixNestedRefRelationshipEditionOverview, { stixNestedRefRelationshipEditionQuery } from './StixNestedRefRelationshipEditionOverview';

const stixNestedRefRelationshipEditionContextQuery = graphql`
  query StixNestedRefRelationshipEditionContextQuery($id: String!) {
    stixRefRelationship(id: $id) {
      editContext {
        name
        focusOn
      }
    }
  }
`;

interface StixNestedRefRelationshipEditionProps {
  stixNestedRefRelationshipId: string;
  open: boolean;
  handleClose?: () => void;
}
const StixNestedRefRelationshipEdition: FunctionComponent<StixNestedRefRelationshipEditionProps> = ({
  stixNestedRefRelationshipId,
  open,
  handleClose,
}) => {
  const contextQueryRef = useQueryLoading<StixNestedRefRelationshipEditionContextQuery>(
    stixNestedRefRelationshipEditionContextQuery,
    { id: stixNestedRefRelationshipId },
  );

  if (!contextQueryRef) return null;

  return (
    <StixNestedRefRelationshipEditionContent
      stixNestedRefRelationshipId={stixNestedRefRelationshipId}
      open={open}
      handleClose={handleClose}
      contextQueryRef={contextQueryRef}
    />
  );
};

const StixNestedRefRelationshipEditionContent: FunctionComponent<
  StixNestedRefRelationshipEditionProps & {
    contextQueryRef: PreloadedQuery<StixNestedRefRelationshipEditionContextQuery>;
  }
> = ({
  stixNestedRefRelationshipId,
  open,
  handleClose,
  contextQueryRef,
}) => {
  const { t_i18n } = useFormatter();

  const contextData = usePreloadedQuery(
    stixNestedRefRelationshipEditionContextQuery,
    contextQueryRef,
  );

  const editContext = contextData?.stixRefRelationship?.editContext;

  const queryRef = useQueryLoading<StixNestedRefRelationshipEditionOverviewQuery>(
    stixNestedRefRelationshipEditionQuery,
    { id: stixNestedRefRelationshipId },
  );

  return (
    <Drawer
      open={open}
      title={t_i18n('Update a relationship')}
      onClose={handleClose}
      context={editContext}
    >
      {queryRef ? (
        <React.Suspense fallback={<Loader variant={LoaderVariant.inline} />}>
          <StixNestedRefRelationshipEditionOverview
            queryRef={queryRef}
            handleClose={handleClose}
          />
        </React.Suspense>
      ) : (
        <Loader variant={LoaderVariant.inline} />
      )}
    </Drawer>
  );
};

export default StixNestedRefRelationshipEdition;
