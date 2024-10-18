import React, { Component } from 'react';
import PropTypes from 'prop-types';
import { compose } from 'ramda';
import { graphql, createFragmentContainer } from 'react-relay';
import withStyles from '@mui/styles/withStyles';
import Paper from '@mui/material/Paper';
import Typography from '@mui/material/Typography';
import Grid from '@mui/material/Grid';
import * as R from 'ramda';
import inject18n from '../../../../components/i18n';
import ExpandableMarkdown from '../../../../components/ExpandableMarkdown';
import ItemOpenVocab from '../../../../components/ItemOpenVocab';

const styles = (theme) => ({
  paper: {
    marginTop: theme.spacing(1),
    padding: '15px',
    borderRadius: 4,
  },
});

class EventDetailsComponent extends Component {
  render() {
    const { fldt, t, classes, event } = this.props;
    return (
      <div style={{ height: '100%' }}>
        <Typography variant="h4" gutterBottom={true}>
          {t('Details')}
        </Typography>
        <Paper classes={{ root: classes.paper }} className={'paper-for-grid'} variant="outlined">
          <Grid container={true} spacing={3}>
            <Grid item xs={6}>
              <Typography variant="h3" gutterBottom={true}>
                {t('Description')}
              </Typography>
              <ExpandableMarkdown source={event.description} limit={400} />
              <Typography
                variant="h3"
                gutterBottom={true}
                style={{ marginTop: 20 }}
              >
                {t('Event types')}
              </Typography>
              {R.propOr(['-'], 'event_types', event).map((eventType) => (
                <div key={`event_type_ov_${eventType}`} style={{ marginBottom: 10 }}>
                  <ItemOpenVocab key="type" small={true} type="event_type_ov" value={eventType}/>
                </div>
              ))}
            </Grid>
            <Grid item xs={6}>
              <Typography variant="h3" gutterBottom={true}>
                {t('Start date')}
              </Typography>
              {fldt(event.start_time)}
              <Typography
                variant="h3"
                gutterBottom={true}
                style={{ marginTop: 20 }}
              >
                {t('End date')}
              </Typography>
              {fldt(event.stop_time)}
            </Grid>
          </Grid>
        </Paper>
      </div>
    );
  }
}

EventDetailsComponent.propTypes = {
  event: PropTypes.object,
  classes: PropTypes.object,
  t: PropTypes.func,
  fldt: PropTypes.func,
};

const EventDetails = createFragmentContainer(EventDetailsComponent, {
  event: graphql`
    fragment EventDetails_event on Event {
      id
      description
      event_types
      start_time
      stop_time
    }
  `,
});

export default compose(inject18n, withStyles(styles))(EventDetails);
