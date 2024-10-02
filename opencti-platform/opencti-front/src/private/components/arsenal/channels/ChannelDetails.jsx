import React, { Component } from 'react';
import * as PropTypes from 'prop-types';
import * as R from 'ramda';
import { graphql, createFragmentContainer } from 'react-relay';
import withStyles from '@mui/styles/withStyles';
import Paper from '@mui/material/Paper';
import Typography from '@mui/material/Typography';
import Grid from '@mui/material/Grid';
import Chip from '@mui/material/Chip';
import inject18n from '../../../../components/i18n';
import ExpandableMarkdown from '../../../../components/ExpandableMarkdown';

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
      <>
        <Typography variant="h4" gutterBottom={true}>
          {t('Details')}
        </Typography>
        <Paper classes={{ root: classes.paper }} className={'paper-for-grid'} variant="outlined">
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
              {R.propOr(['-'], 'channel_types', channel).map((channelType) => (
                <Chip
                  key={channelType}
                  classes={{ root: classes.chip }}
                  label={channelType}
                />
              ))}
            </Grid>
          </Grid>
        </Paper>
      </>
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
