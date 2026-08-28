import React from 'react';
import * as PropTypes from 'prop-types';
import { graphql, createFragmentContainer } from 'react-relay';
import Grid from '@mui/material/Grid';
import Card from '@common/card/Card';
import { useFormatter } from '../../../../components/i18n';
import ExpandableMarkdown from '../../../../components/ExpandableMarkdown';
import NarrativeParentNarratives from './NarrativeParentNarratives';
import NarrativeSubNarratives from './NarrativeSubNarratives';
import Label from '../../../../components/common/label/Label';

const NarrativeDetailsComponent = (props) => {
  const { t_i18n } = useFormatter();
  const { narrative } = props;
  return (
    <div style={{ height: '100%' }}>
      <Card title={t_i18n('Details')}>
        <Grid container={true} spacing={3}>
          <Grid item xs={12}>
            <Label>
              {t_i18n('Description')}
            </Label>
            <ExpandableMarkdown source={narrative.description} limit={400} />
          </Grid>
          <Grid item xs={6}>
            {narrative.isSubNarrative ? (
              <NarrativeParentNarratives narrative={narrative} />
            ) : (
              <NarrativeSubNarratives narrative={narrative} />
            )}
          </Grid>
        </Grid>
      </Card>
    </div>
  );
};

NarrativeDetailsComponent.propTypes = {
  narrative: PropTypes.object,
};

const NarrativeDetails = createFragmentContainer(NarrativeDetailsComponent, {
  narrative: graphql`
    fragment NarrativeDetails_narrative on Narrative {
      id
      description
      isSubNarrative
      ...NarrativeSubNarratives_narrative
      ...NarrativeParentNarratives_narrative
    }
  `,
});

export default NarrativeDetails;
