import React, { Component } from 'react';
import * as PropTypes from 'prop-types';
import { compose } from 'ramda';
import { createFragmentContainer, graphql } from 'react-relay';
import withStyles from '@mui/styles/withStyles';
import Paper from '@mui/material/Paper';
import Typography from '@mui/material/Typography';
import Grid from '@mui/material/Grid';
import inject18n from '../../../../components/i18n';
import ExpandableMarkdown from '../../../../components/ExpandableMarkdown';
import ItemOpenVocab from '../../../../components/ItemOpenVocab';
import MarkdownDisplay from '../../../../components/MarkdownDisplay';

const styles = () => ({
  paper: {
    height: '100%',
    minHeight: '100%',
    margin: '10px 0 0 0',
    padding: '15px',
    borderRadius: 6,
  },
  item: {
    paddingLeft: 10,
    transition: 'background-color 0.1s ease',
    '&:hover': {
      background: 'rgba(0, 0, 0, 0.1)',
    },
  },
});

class SystemDetailsComponent extends Component {
  render() {
    const { t, classes, system } = this.props;
    return (
      <div style={{ height: '100%' }}>
        <Typography variant="h4" gutterBottom={true}>
          {t('Details')}
        </Typography>
        <Paper classes={{ root: classes.paper }} variant="outlined">
          <Grid container={true} spacing={3}>
            <Grid item={true} xs={6}>
              <Typography variant="h3" gutterBottom={true}>
                {t('Description')}
              </Typography>
              <ExpandableMarkdown source={system.description} limit={400} />
            </Grid>
            <Grid item={true} xs={6}>
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
        </Paper>
      </div>
    );
  }
}

SystemDetailsComponent.propTypes = {
  system: PropTypes.object,
  classes: PropTypes.object,
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

export default compose(inject18n, withStyles(styles))(SystemDetails);
