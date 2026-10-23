import { MessageOutlined, MoreVert } from '@mui/icons-material';
import ListItem from '@mui/material/ListItem';
import ListItemIcon from '@mui/material/ListItemIcon';
import ListItemText from '@mui/material/ListItemText';
import Skeleton from '@mui/material/Skeleton';
import { styled } from '@mui/material/styles';
import React from 'react';
import { graphql, useFragment } from 'react-relay';
import IconButton from '@common/button/IconButton';
import Box from '@mui/material/Box';
import ErrorNotFound from '../../../../components/ErrorNotFound';
import { DataColumns } from '../../../../components/list_lines';
import { SettingsMessagesLine_settingsMessage$key } from './__generated__/SettingsMessagesLine_settingsMessage.graphql';
import SettingsMessagesPopover from './SettingsMessagesPopover';
import { useFormatter } from '../../../../components/i18n';

const BodyItem = styled('div')(({ theme }) => ({
  fontSize: theme.typography.h3.fontSize,
  display: 'flex',
  whiteSpace: 'nowrap',
  overflow: 'hidden',
  textOverflow: 'ellipsis',
  paddingRight: theme.spacing(1),
  alignItems: 'center',
  minWidth: 0,
  width: '100%',
}));

const BodyItemText = styled('span')({
  overflow: 'hidden',
  textOverflow: 'ellipsis',
  whiteSpace: 'nowrap',
  minWidth: 0,
  flex: 1,
});

const settingsMessageFragment = graphql`
  fragment SettingsMessagesLine_settingsMessage on SettingsMessage {
    id
    message
    activated
    dismissible
    updated_at
    color
    recipients {
      id
      name
    }
  }
`;

const SettingsMessagesLine = ({
  entityId,
  node,
  dataColumns,
}: {
  entityId: string;
  node: SettingsMessagesLine_settingsMessage$key;
  dataColumns: DataColumns;
}) => {
  const message = useFragment(settingsMessageFragment, node);
  if (!node || !message) {
    return <ErrorNotFound />;
  }
  return (
    <ListItem
      key={message.id}
      divider={true}
      sx={{ paddingLeft: 1, height: '50px' }}
      secondaryAction={<SettingsMessagesPopover settingsId={entityId} message={message} />}
    >
      <ListItemIcon sx={{ color: (theme) => theme.palette.primary.main }}>
        <MessageOutlined />
      </ListItemIcon>
      <ListItemText
        primary={(
          <div style={{ display: 'flex' }}>
            {Object.values(dataColumns ?? {}).map((value) => (
              <BodyItem
                key={value.label}
                style={{ width: value.width }}
              >
                <BodyItemText>
                  {value.render?.(message)}
                </BodyItemText>
              </BodyItem>
            ))}
          </div>
        )}
      />
    </ListItem>
  );
};

export default SettingsMessagesLine;

export const SettingsMessagesLineDummy = ({
  dataColumns,
}: {
  dataColumns: DataColumns;
}) => {
  const { t_i18n } = useFormatter();
  return (
    <ListItem
      divider={true}
      sx={{ paddingLeft: 1, height: '50px' }}
      secondaryAction={(
        <Box>
          <IconButton aria-label={t_i18n('Open menu')} disabled={true}>
            <MoreVert />
          </IconButton>
        </Box>
      )}
    >
      <ListItemText
        primary={(
          <div style={{ display: 'flex' }}>
            {Object.values(dataColumns).map((value) => (
              <BodyItem
                key={value.label}
                style={{ width: value.width }}
              >
                <BodyItemText>
                  <Skeleton
                    animation="wave"
                    variant="rectangular"
                    width="90%"
                    height={20}
                  />
                </BodyItemText>
              </BodyItem>
            ))}
          </div>
        )}
      />
    </ListItem>
  );
};
