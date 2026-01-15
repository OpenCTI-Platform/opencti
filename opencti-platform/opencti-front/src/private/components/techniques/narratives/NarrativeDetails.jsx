import React, { Component } from 'react';
import * as PropTypes from 'prop-types';
import * as R from 'ramda';
import { graphql, createFragmentContainer } from 'react-relay';
import Grid from '@mui/material/Grid';
import Card from '@common/card/Card';
import inject18n from '../../../../components/i18n';
import ExpandableMarkdown from '../../../../components/ExpandableMarkdown';
import NarrativeParentNarratives from './NarrativeParentNarratives';
import NarrativeSubNarratives from './NarrativeSubNarratives';
import Label from '../../../../components/common/label/Label';

class NarrativeDetailsComponent extends Component {
  render() {
    const { t, narrative } = this.props;
    return (
      <div style={{ height: '100%' }}>
        <Card title={t('Details')}>
          <Grid container={true} spacing={3}>
            <Grid item xs={6}>
              <Label>
                {t('Description')}
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
  }
}

NarrativeDetailsComponent.propTypes = {
  narrative: PropTypes.object,
  t: PropTypes.func,
  fld: PropTypes.func,
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

export default R.compose(inject18n)(NarrativeDetails);
