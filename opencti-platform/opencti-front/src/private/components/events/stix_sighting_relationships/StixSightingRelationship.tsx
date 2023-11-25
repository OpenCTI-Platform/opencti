import React, { FunctionComponent } from 'react';
import { useParams } from 'react-router-dom';
import makeStyles from '@mui/styles/makeStyles';
import { graphql } from 'react-relay';
import StixSightingRelationshipOverview from './StixSightingRelationshipOverview';
import Loader from '../../../../components/Loader';
import { StixSightingRelationshipQuery$data } from './__generated__/StixSightingRelationshipQuery.graphql';
import { QueryRenderer } from '../../../../relay/environment';

const useStyles = makeStyles(() => ({
  container: {
    marginTop: 10,
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
  return (
    <div className={classes.container}>
      <QueryRenderer
        query={stixSightingRelationshipQuery}
        variables={{ id: sightingId }}
        render={(result: { props: StixSightingRelationshipQuery$data }) => {
          if (result.props && result.props.stixSightingRelationship) {
            return (
              <StixSightingRelationshipOverview
                entityId={entityId}
                stixSightingRelationship={result.props.stixSightingRelationship}
                paddingRight={paddingRight}
              />
            );
          }
          return <Loader />;
        }}
      />
    </div>
  );
};

export default StixSightingRelationship;
