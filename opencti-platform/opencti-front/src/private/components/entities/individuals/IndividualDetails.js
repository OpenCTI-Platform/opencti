import React, { Component } from 'react';
import * as PropTypes from 'prop-types';
import * as R from 'ramda';
import { graphql, createFragmentContainer } from 'react-relay';
import withStyles from '@mui/styles/withStyles';
import Paper from '@mui/material/Paper';
import Typography from '@mui/material/Typography';
import Grid from '@mui/material/Grid';
import inject18n from '../../../../components/i18n';
import ExpandableMarkdown from '../../../../components/ExpandableMarkdown';

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

class IndividualDetailsComponent extends Component {
  render() {
    const { t, classes, individual } = this.props;
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
              <ExpandableMarkdown source={individual.description} limit={400} />
            </Grid>
            <Grid item={true} xs={6}>
              <Typography variant="h3" gutterBottom={true}>
                {t('Contact information')}
              </Typography>
              <pre>{individual.contact_information}</pre>
            </Grid>
          </Grid>
        </Paper>
      </div>
    );
  }
}

IndividualDetailsComponent.propTypes = {
  individual: PropTypes.object,
  classes: PropTypes.object,
  t: PropTypes.func,
  fld: PropTypes.func,
};

const IndividualDetails = createFragmentContainer(IndividualDetailsComponent, {
  individual: graphql`
    fragment IndividualDetails_individual on Individual {
      id
      contact_information
      description
    }
  `,
});

export default R.compose(inject18n, withStyles(styles))(IndividualDetails);
