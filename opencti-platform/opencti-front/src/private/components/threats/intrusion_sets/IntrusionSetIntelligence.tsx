import React from 'react';
import { graphql, useFragment } from 'react-relay';
import Grid from '@mui/material/Grid';
import parse from 'html-react-parser';
import { IntrusionSetIntelligence_intrusionSet$key } from './__generated__/IntrusionSetIntelligence_intrusionSet.graphql';

const intrusionSetIntelligenceFragment = graphql`
  fragment IntrusionSetIntelligence_intrusionSet on IntrusionSet {
    id
    intelligence {
      trends
    }
  }
`;

interface IntrusionSetIntelligenceProps {
  intrusionSetData: IntrusionSetIntelligence_intrusionSet$key;
}

const IntrusionSetIntelligence: React.FC<IntrusionSetIntelligenceProps> = ({ intrusionSetData }) => {
  const intrusionSet = useFragment<IntrusionSetIntelligence_intrusionSet$key>(intrusionSetIntelligenceFragment, intrusionSetData);
  console.log(intrusionSet);
  return (
    <>
      <Grid
        container={true}
        spacing={3}
        style={{ marginBottom: 20 }}
      >
        <Grid item xs={6}>
          {parse(intrusionSet?.intelligence?.trends ?? '')}
        </Grid>
      </Grid>
    </>
  );
};

export default IntrusionSetIntelligence;
