import React, { Component } from 'react';
import * as PropTypes from 'prop-types';
import { compose } from 'ramda';
import { createFragmentContainer, graphql } from 'react-relay';
import Typography from '@mui/material/Typography';
import Grid from '@mui/material/Grid';
import Card from '@common/card/Card';
import inject18n from '../../../../components/i18n';
import ExpandableMarkdown from '../../../../components/ExpandableMarkdown';
import ItemOpenVocab from '../../../../components/ItemOpenVocab';
import MarkdownDisplay from '../../../../components/MarkdownDisplay';

class SystemDetailsComponent extends Component {
  render() {
    const { t, system } = this.props;
    return (
      <div style={{ height: '100%' }}>
        <Card title={t('Details')}>
          <Grid container={true} spacing={3}>
            <Grid item xs={6}>
              <Typography variant="h3" gutterBottom={true}>
                {t('Description')}
              </Typography>
              <ExpandableMarkdown source={system.description} limit={400} />
            </Grid>
            <Grid item xs={6}>
              <Typography variant="h3" gutterBottom={true}>
                {t('Reliability')}
              </Typography>
              <ItemOpenVocab
                displayMode="chip"
                type="reliability_ov"
                value={system.x_opencti_reliability}
              />
              <Typography variant="h3" gutterBottom={true} style={{ marginTop: 20 }}>
                {t('Contact information')}
              </Typography>
              <MarkdownDisplay
                content={system.contact_information}
                remarkGfmPlugin={true}
                commonmark={true}
              />
            </Grid>
          </Grid>
        </Card>
      </div>
    );
  }
}

SystemDetailsComponent.propTypes = {
  system: PropTypes.object,
  t: PropTypes.func,
  fld: PropTypes.func,
};

const SystemDetails = createFragmentContainer(SystemDetailsComponent, {
  system: graphql`
    fragment SystemDetails_system on System {
      id
      contact_information
      description
      x_opencti_reliability
    }
  `,
});

export default compose(inject18n)(SystemDetails);
