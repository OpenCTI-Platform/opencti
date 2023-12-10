import { Add } from '@mui/icons-material';
import IconButton from '@mui/material/IconButton';
import Paper from '@mui/material/Paper';
import Typography from '@mui/material/Typography';
import { makeStyles } from '@mui/styles';
import React, { useState } from 'react';
import { graphql, useFragment } from 'react-relay';
import Tooltip from '@mui/material/Tooltip';
import { SettingsMessagesLine_settingsMessage$data } from '@components/settings/settings_messages/__generated__/SettingsMessagesLine_settingsMessage.graphql';
import { useFormatter } from '../../../../components/i18n';
import { DataColumns } from '../../../../components/list_lines';
import ListLines from '../../../../components/list_lines/ListLines';
import { Theme } from '../../../../components/Theme';
import { generateBannerMessageColors } from '../../../../utils/Colors';
import { SettingsMessages_settingsMessages$key } from './__generated__/SettingsMessages_settingsMessages.graphql';
import SettingsMessageCreation from './SettingsMessageCreation';
import SettingsMessagesLines from './SettingsMessagesLines';
import ItemBoolean from '../../../../components/ItemBoolean';

const useStyles = makeStyles<Theme>((theme) => ({
  paper: {
    height: '100%',
    minHeight: '100%',
    marginTop: theme.spacing(1.5),
    padding: '10px 20px 10px 20px',
    borderRadius: 6,
  },
}));

const settingsMessagesFragment = graphql`
  fragment SettingsMessages_settingsMessages on Settings {
    messages {
      ...SettingsMessagesLine_settingsMessage
    }
  }
`;

const SettingsMessages = ({
  settings,
}: {
  settings: SettingsMessages_settingsMessages$key & { readonly id: string };
}) => {
  const { t } = useFormatter();
  const classes = useStyles();
  const messages = useFragment<SettingsMessages_settingsMessages$key>(
    settingsMessagesFragment,
    settings,
  )?.messages ?? [];
  const dataColumns: DataColumns = {
    color: {
      label: 'Color',
      width: '10%',
      isSortable: false,
      render: (data) => {
        const { backgroundColor, borderLeft, color } = generateBannerMessageColors(data?.color);
        return (
          <div
            style={{
              backgroundColor,
              borderLeft,
              color,
              textAlign: 'center',
              fontWeight: 500,
              width: '70%',
            }}
          >
            {t('Sample')}
          </div>
        );
      },
    },
    message: {
      label: 'Message',
      width: '40%',
      isSortable: false,
      render: (data) => <div>{data.message}</div>,
    },
    status: {
      label: 'Status',
      width: '15%',
      isSortable: false,
      render: (data) => {
        return (
          <ItemBoolean
            variant="inList"
            label={data.activated ? t('Enabled') : t('Disabled')}
            status={data.activated}
          />
        );
      },
    },
    dismissible: {
      label: 'Dismissible',
      width: '20%',
      isSortable: false,
      render: (data) => {
        return (
          <ItemBoolean
            variant="inList"
            label={data.dismissible ? t('Yes') : t('No')}
            status={data.dismissible}
          />
        );
      },
    },
    recipients: {
      label: 'recipients',
      width: '15%',
      isSortable: false,
      render: (data: SettingsMessagesLine_settingsMessage$data) => (
        <Tooltip title={data.recipients?.map(({ name }) => name).join(', ')}>
          <span>{data.recipients?.map(({ name }) => name).join(', ')}</span>
        </Tooltip>
      ),
    },
  };
  const datas = messages.map((m) => ({ node: m }));
  const [displayCreate, setDisplayCreate] = useState(false);
  const handleOpenCreate = () => setDisplayCreate(true);
  const handleCloseCreate = () => setDisplayCreate(false);
  return (
    <>
      <Typography variant="h4" gutterBottom={true} style={{ float: 'left' }}>
        {t('Platform announcement')}
      </Typography>
      <IconButton
        style={{ float: 'left', marginTop: -15 }}
        color="primary"
        aria-label="Add"
        onClick={handleOpenCreate}
        size="large"
      >
        <Add fontSize="small" />
      </IconButton>
      <div className="clearfix" />
      <Paper
        classes={{ root: classes.paper }}
        variant="outlined"
        style={{ marginTop: 0 }}
      >
        <ListLines
          dataColumns={dataColumns}
          noFilters
          noPadding
          secondaryAction
        >
          <SettingsMessagesLines
            settingsId={settings.id}
            datas={datas}
            dataColumns={dataColumns}
          />
        </ListLines>
      </Paper>
      <SettingsMessageCreation
        settingsId={settings.id}
        handleClose={handleCloseCreate}
        open={displayCreate}
      />
    </>
  );
};

export default SettingsMessages;
