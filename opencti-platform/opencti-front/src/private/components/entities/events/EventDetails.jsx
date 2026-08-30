import React from 'react';
import PropTypes from 'prop-types';
import { createFragmentContainer, graphql } from 'react-relay';
import Grid from '@mui/material/Grid';
import Card from '@common/card/Card';
import { useFormatter } from '../../../../components/i18n';
import ExpandableMarkdown from '../../../../components/ExpandableMarkdown';
import ItemOpenVocab from '../../../../components/ItemOpenVocab';
import ItemScore from '../../../../components/ItemScore';
import FieldOrEmpty from '../../../../components/FieldOrEmpty';
import Label from '../../../../components/common/label/Label';
import { Stack } from '@mui/material';

const EventDetailsComponent = (props) => {
  const { fldt, t_i18n } = useFormatter();
  const { event } = props;
  return (
    <div style={{ height: '100%' }}>
      <Card title={t_i18n('Details')}>
        <Grid container={true} spacing={2}>
          <Grid item xs={12}>
            <Label>
              {t_i18n('Description')}
            </Label>
            <ExpandableMarkdown source={event.description} limit={400} />
          </Grid>
          <Grid item xs={6}>
            <Label>
              {t_i18n('Event types')}
            </Label>
            <FieldOrEmpty source={event.event_types}>
              <Stack direction="row" gap={1} flexWrap="wrap">
                {event.event_types?.map((eventType) => (
                  <ItemOpenVocab key="type" small={true} type="event_type_ov" value={eventType} />
                ))}
              </Stack>
            </FieldOrEmpty>
          </Grid>
          <Grid item xs={6}>
            <Label>
              {t_i18n('Start date')}
            </Label>
            {fldt(event.start_time)}
            <Label
              sx={{ marginTop: 2 }}
            >
              {t_i18n('End date')}
            </Label>
            {fldt(event.stop_time)}
            <Label
              sx={{ marginTop: 2 }}
            >
              {t_i18n('Score')}
            </Label>
            <ItemScore score={event.x_opencti_score} />
          </Grid>
        </Grid>
      </Card>
    </div>
  );
};

EventDetailsComponent.propTypes = {
  event: PropTypes.object,
};

const EventDetails = createFragmentContainer(EventDetailsComponent, {
  event: graphql`
    fragment EventDetails_event on Event {
      id
      description
      event_types
      start_time
      stop_time
      x_opencti_score
    }
  `,
});

export default EventDetails;
