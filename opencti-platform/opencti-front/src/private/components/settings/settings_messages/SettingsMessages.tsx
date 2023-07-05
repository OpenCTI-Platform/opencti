import Typography from '@mui/material/Typography';
import React, { useState } from 'react';
import { makeStyles } from '@mui/styles';
import Paper from '@mui/material/Paper';
import { graphql, useFragment } from 'react-relay';
import Chip from '@mui/material/Chip';
import IconButton from '@mui/material/IconButton';
import { Add } from '@mui/icons-material';
import Drawer from '@mui/material/Drawer';
import { useFormatter } from '../../../../components/i18n';
import ListLines from '../../../../components/list_lines/ListLines';
import SettingsMessagesLines from './SettingsMessagesLines';
import { Theme } from '../../../../components/Theme';
import { SettingsMessagesLine_settingsMessage$data } from './__generated__/SettingsMessagesLine_settingsMessage.graphql';
import { SettingsMessages_settingsMessages$key } from './__generated__/SettingsMessages_settingsMessages.graphql';
import SettingsMessageCreation from './SettingsMessageCreation';

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
  settings: SettingsMessages_settingsMessages$key & { readonly id: string }
}) => {
  const { t } = useFormatter();
  const classes = useStyles();

  const messages = useFragment<SettingsMessages_settingsMessages$key>(settingsMessagesFragment, settings)?.messages ?? [];

  const dataColumns = {
    message: {
      label: 'Message',
      width: '70%',
      isSortable: false,
      render: (data: SettingsMessagesLine_settingsMessage$data) => data.message,
    },
    status: {
      label: 'Status',
      width: '15%',
      isSortable: false,
      render: (data: SettingsMessagesLine_settingsMessage$data) => {
        const color = data.activated ? 'primary' : 'secondary';
        const label = data.activated ? 'Active' : 'Inactive';
        return (
          <Chip
            classes={{ root: classes.chipInList }}
            color={color}
            variant="outlined"
            label={t(label)}
          />
        );
      },
    },
    dismissible: {
      label: 'Dismissible',
      width: '15%',
      isSortable: false,
      render: (data: SettingsMessagesLine_settingsMessage$data) => {
        const color = data.dismissible ? 'primary' : 'secondary';
        const label = data.dismissible ? 'Yes' : 'No';
        return (
          <Chip
            classes={{ root: classes.chipInList }}
            color={color}
            variant="outlined"
            label={t(label)}
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
      <div className={classes.container}>
        <Typography variant="h4" gutterBottom={true}>
          {t('Platform announcement')}
        </Typography>
        <IconButton style={{ marginTop: -5 }}
                    color="secondary"
                    aria-label="Add"
                    onClick={handleOpenCreate}
                    size="large"
        >
          <Add fontSize="small" />
        </IconButton>
      </div>
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
      <Paper classes={{ root: classes.paper }} variant="outlined" style={{ marginTop: 0 }}>
        <ListLines dataColumns={dataColumns} noFilters={true} noPadding={true}>
        <SettingsMessagesLines settingsId={settings.id} datas={datas} dataColumns={dataColumns} />
        </ListLines>
      </Paper>
    </>
  );
};

export default SettingsMessages;
