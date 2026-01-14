import React from 'react';
import { graphql, useFragment } from 'react-relay';
import Typography from '@mui/material/Typography';
import Grid from '@mui/material/Grid';
import Chip from '@mui/material/Chip';
import Card from '@common/card/Card';
import { useFormatter } from '../../../../components/i18n';
import ExpandableMarkdown from '../../../../components/ExpandableMarkdown';
import FieldOrEmpty from '../../../../components/FieldOrEmpty';
import { useTheme } from '@mui/styles';

const ChannelDetailsFragment = graphql`
  fragment ChannelDetails_channel on Channel {
    id
    description
    channel_types
  }
`;

export const ChannelDetails = ({
  channelData,
}) => {
  const { t_i18n } = useFormatter();
  const theme = useTheme();
  const channel = useFragment(ChannelDetailsFragment, channelData);
  return (
    <Card title={t_i18n('Details')}>
      <Grid container={true} spacing={3}>
        <Grid item xs={6}>
          <Typography variant="h3" gutterBottom={true}>
            {t_i18n('Description')}
          </Typography>
          <ExpandableMarkdown source={channel.description} limit={400} />
        </Grid>
        <Grid item xs={6}>
          <Typography variant="h3" gutterBottom={true}>
            {t_i18n('Channel types')}
          </Typography>
          <FieldOrEmpty source={channel.channel_types}>
            {channel.channel_types?.map((channelType) => (
              <Chip
                key={channelType}
                label={channelType}
                style={{
                  fontSize: 12,
                  lineHeight: '12px',
                  backgroundColor: theme.palette.background.accent,
                  color: theme.palette.text.primary,
                  textTransform: 'uppercase',
                  borderRadius: 4,
                  margin: '0 5px 5px 0',
                }}
              />
            ))}
          </FieldOrEmpty>
        </Grid>
      </Grid>
    </Card>
  );
};

export default ChannelDetails;
