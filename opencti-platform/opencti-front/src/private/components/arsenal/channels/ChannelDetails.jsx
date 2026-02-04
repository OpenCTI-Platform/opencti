import React from 'react';
import { graphql, useFragment } from 'react-relay';
import Grid from '@mui/material/Grid';
import { Stack } from '@mui/material';
import Card from '@common/card/Card';
import { useFormatter } from '../../../../components/i18n';
import ExpandableMarkdown from '../../../../components/ExpandableMarkdown';
import FieldOrEmpty from '../../../../components/FieldOrEmpty';
import Label from '../../../../components/common/label/Label';
import Tag from '@common/tag/Tag';

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
  const channel = useFragment(ChannelDetailsFragment, channelData);
  return (
    <Card title={t_i18n('Details')}>
      <Grid container={true} spacing={2}>
        <Grid item xs={6}>
          <Label>
            {t_i18n('Description')}
          </Label>
          <ExpandableMarkdown source={channel.description} limit={400} />
        </Grid>
        <Grid item xs={6}>
          <Label>
            {t_i18n('Channel types')}
          </Label>
          <FieldOrEmpty source={channel.channel_types}>
            <Stack direction="row" gap={1} flexWrap="wrap">
              {channel.channel_types?.map((channelType) => (
                <Tag
                  key={channelType}
                  label={channelType}
                />
              ))}
            </Stack>
          </FieldOrEmpty>
        </Grid>
      </Grid>
    </Card>
  );
};

export default ChannelDetails;
