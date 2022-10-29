import React, { FunctionComponent, Suspense } from 'react';
import { useParams } from 'react-router-dom';
import makeStyles from '@mui/styles/makeStyles';
import { graphql, useLazyLoadQuery } from 'react-relay';
import StixSightingRelationshipOverview from './StixSightingRelationshipOverview';
import Loader from '../../../../components/Loader';
import { StixSightingRelationshipQuery } from './__generated__/StixSightingRelationshipQuery.graphql';

const useStyles = makeStyles(() => ({
  container: {
    margin: 0,
  },
}));

const stixSightingRelationshipQuery = graphql`
  query StixSightingRelationshipQuery($id: String!) {
    stixSightingRelationship(id: $id) {
      ...StixSightingRelationshipOverview_stixSightingRelationship
    }
  }
`;

interface StixSightingRelationshipProps {
  entityId: string;
  paddingRight: boolean;
}

const StixSightingRelationship: FunctionComponent<
StixSightingRelationshipProps
> = ({ entityId, paddingRight }) => {
  const classes = useStyles();
  const { sightingId } = useParams() as { sightingId: string };
  const data = useLazyLoadQuery<StixSightingRelationshipQuery>(
    stixSightingRelationshipQuery,
    { id: sightingId },
  );
  return (
    <div className={classes.container}>
      <Suspense fallback={<Loader />}>
        <StixSightingRelationshipOverview
          entityId={entityId}
          stixSightingRelationship={data.stixSightingRelationship}
          paddingRight={paddingRight}
        />
      </Suspense>
    </div>
  );
};

export default StixSightingRelationship;
