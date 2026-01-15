import React, { Component } from 'react';
import PropTypes from 'prop-types';
import { compose } from 'ramda';
import { createFragmentContainer, graphql } from 'react-relay';
import Grid from '@mui/material/Grid';
import Card from '@common/card/Card';
import inject18n from '../../../../components/i18n';
import ExpandableMarkdown from '../../../../components/ExpandableMarkdown';
import ItemOpenVocab from '../../../../components/ItemOpenVocab';
import FieldOrEmpty from '../../../../components/FieldOrEmpty';
import Label from '../../../../components/common/label/Label';

class EventDetailsComponent extends Component {
  render() {
    const { fldt, t, event } = this.props;
    return (
      <div style={{ height: '100%' }}>
        <Card title={t('Details')}>
          <Grid container={true} spacing={2}>
            <Grid item xs={6}>
              <Label>
                {t('Description')}
              </Label>
              <ExpandableMarkdown source={event.description} limit={400} />
              <Label
                sx={{ marginTop: 2 }}
              >
                {t('Event types')}
              </Label>
              <FieldOrEmpty source={event.event_types}>
                {event.event_types?.map((eventType) => (
                  <div key={`event_type_ov_${eventType}`} style={{ marginBottom: 10 }}>
                    <ItemOpenVocab key="type" small={true} type="event_type_ov" value={eventType} />
                  </div>
                ))}
              </FieldOrEmpty>
            </Grid>
            <Grid item xs={6}>
              <Label>
                {t('Start date')}
              </Label>
              {fldt(event.start_time)}
              <Label
                sx={{ marginTop: 2 }}
              >
                {t('End date')}
              </Label>
              {fldt(event.stop_time)}
            </Grid>
          </Grid>
        </Card>
      </div>
    );
  }
}

EventDetailsComponent.propTypes = {
  event: PropTypes.object,
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

export default compose(inject18n)(EventDetails);
