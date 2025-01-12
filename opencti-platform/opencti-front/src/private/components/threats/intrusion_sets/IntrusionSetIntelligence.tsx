import React from 'react';
import { graphql, useFragment } from 'react-relay';
import Grid from '@mui/material/Grid';
import parse from 'html-react-parser';
import ContainersAiSummary from '@components/common/containers/ContainersAiSummary';
import { IntrusionSetIntelligence_intrusionSet$key } from './__generated__/IntrusionSetIntelligence_intrusionSet.graphql';

const intrusionSetIntelligenceFragment = graphql`
  fragment IntrusionSetIntelligence_intrusionSet on IntrusionSet {
    id
  }
`;

interface IntrusionSetIntelligenceProps {
  intrusionSetData: IntrusionSetIntelligence_intrusionSet$key;
}

const IntrusionSetIntelligence: React.FC<IntrusionSetIntelligenceProps> = ({ intrusionSetData }) => {
  const intrusionSet = useFragment<IntrusionSetIntelligence_intrusionSet$key>(intrusionSetIntelligenceFragment, intrusionSetData);
  const containersFilters = {
    mode: 'and',
    filters: [
      { key: 'entity_type', values: ['Report'] },
      { key: 'objects', values: [intrusionSet.id] },
    ],
    filterGroups: [],
  };
  return (
    <>
      <Grid
        container={true}
        spacing={3}
        style={{ marginBottom: 20 }}
      >
        <Grid item xs={6}>
          <ContainersAiSummary first={10} filters={containersFilters} />
        </Grid>
      </Grid>
    </>
  );
};

export default IntrusionSetIntelligence;
