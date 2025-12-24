import React, { Component } from 'react';
import * as PropTypes from 'prop-types';
import * as R from 'ramda';
import { graphql, createFragmentContainer } from 'react-relay';
import withStyles from '@mui/styles/withStyles';
import Typography from '@mui/material/Typography';
import Grid from '@mui/material/Grid';
import Chip from '@mui/material/Chip';
import Card from '@common/card/Card';
import inject18n from '../../../../components/i18n';
import ExpandableMarkdown from '../../../../components/ExpandableMarkdown';
import FieldOrEmpty from '../../../../components/FieldOrEmpty';

const styles = (theme) => ({
  paper: {
    marginTop: theme.spacing(1),
    padding: '15px',
    borderRadius: 4,
  },
  chip: {
    fontSize: 12,
    lineHeight: '12px',
    backgroundColor: theme.palette.background.accent,
    color: theme.palette.text.primary,
    textTransform: 'uppercase',
    borderRadius: 4,
    margin: '0 5px 5px 0',
  },
});

class ChannelDetailsComponent extends Component {
  render() {
    const { t, classes, channel } = this.props;
    return (
      <Card title={t('Details')}>
        <Grid container={true} spacing={3}>
          <Grid item xs={6}>
            <Typography variant="h3" gutterBottom={true}>
              {t('Description')}
            </Typography>
            <ExpandableMarkdown source={channel.description} limit={400} />
          </Grid>
          <Grid item xs={6}>
            <Typography variant="h3" gutterBottom={true}>
              {t('Channel types')}
            </Typography>
            <FieldOrEmpty source={channel.channel_types}>
              {channel.chanel_types?.map((channelType) => (
                <Chip
                  key={channelType}
                  classes={{ root: classes.chip }}
                  label={channelType}
                />
              ))}
            </FieldOrEmpty>
          </Grid>
        </Grid>
      </Card>
    );
  }
}

ChannelDetailsComponent.propTypes = {
  channel: PropTypes.object,
  classes: PropTypes.object,
  t: PropTypes.func,
  fld: PropTypes.func,
};

const ChannelDetails = createFragmentContainer(ChannelDetailsComponent, {
  channel: graphql`
    fragment ChannelDetails_channel on Channel {
      id
      description
      channel_types
    }
  `,
});

export default R.compose(inject18n, withStyles(styles))(ChannelDetails);
