import { Add } from '@mui/icons-material';
import Drawer from '@mui/material/Drawer';
import IconButton from '@mui/material/IconButton';
import Paper from '@mui/material/Paper';
import Typography from '@mui/material/Typography';
import { makeStyles } from '@mui/styles';
import React, { useState } from 'react';
import { graphql, useFragment } from 'react-relay';
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
  container: {
    display: 'flex',
    alignItems: 'center',
  },
  paper: {
    height: '100%',
    minHeight: '100%',
    marginTop: theme.spacing(1.5),
    padding: theme.spacing(2),
    borderRadius: 6,
  },
  chipInList: {
    fontSize: 12,
    height: 20,
    float: 'left',
    width: 120,
  },
  drawerPaper: {
    minHeight: '100vh',
    width: '50%',
    position: 'fixed',
    overflow: 'auto',
    transition: theme.transitions.create('width', {
      easing: theme.transitions.easing.sharp,
      duration: theme.transitions.duration.enteringScreen,
    }),
    padding: 0,
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
      width: '15%',
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
      width: '50%',
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
      width: '15%',
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
        color="secondary"
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
      <Drawer
        open={displayCreate}
        anchor="right"
        sx={{ zIndex: 1202 }}
        elevation={1}
        classes={{ paper: classes.drawerPaper }}
        onClose={handleCloseCreate}
      >
        <SettingsMessageCreation
          settingsId={settings.id}
          handleClose={handleCloseCreate}
        />
      </Drawer>
    </>
  );
};

export default SettingsMessages;
