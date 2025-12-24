import React, { Component } from 'react';
import * as PropTypes from 'prop-types';
import * as R from 'ramda';
import { graphql, createFragmentContainer } from 'react-relay';
import Typography from '@mui/material/Typography';
import Grid from '@mui/material/Grid';
import Card from '@common/card/Card';
import inject18n from '../../../../components/i18n';
import ExpandableMarkdown from '../../../../components/ExpandableMarkdown';
import FieldOrEmpty from '../../../../components/FieldOrEmpty';
import ItemOpenVocab from '../../../../components/ItemOpenVocab';

class IndividualDetailsComponent extends Component {
  render() {
    const { t, individual } = this.props;
    return (
      <div style={{ height: '100%' }}>
        <Card title={t('Details')}>
          <Grid container={true} spacing={3}>
            <Grid item xs={6}>
              <Typography variant="h3" gutterBottom={true}>
                {t('Description')}
              </Typography>
              <ExpandableMarkdown source={individual.description} limit={400} />
            </Grid>
            <Grid item xs={6}>
              <Typography variant="h3" gutterBottom={true}>
                {t('Reliability')}
              </Typography>
              <ItemOpenVocab
                displayMode="chip"
                type="reliability_ov"
                value={individual.x_opencti_reliability}
              />
              <Typography variant="h3" gutterBottom={true} style={{ marginTop: 20 }}>
                {t('Contact information')}
              </Typography>
              <FieldOrEmpty source={individual.contact_information}>
                <pre>{individual.contact_information}</pre>
              </FieldOrEmpty>
            </Grid>
          </Grid>
        </Card>
      </div>
    );
  }
}

IndividualDetailsComponent.propTypes = {
  individual: PropTypes.object,
  t: PropTypes.func,
  fld: PropTypes.func,
};

const IndividualDetails = createFragmentContainer(IndividualDetailsComponent, {
  individual: graphql`
    fragment IndividualDetails_individual on Individual {
      id
      contact_information
      description
      x_opencti_reliability
    }
  `,
});

export default R.compose(inject18n)(IndividualDetails);
