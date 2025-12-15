import { Add } from '@mui/icons-material';
import IconButton from '@common/button/IconButton';
import Paper from '@mui/material/Paper';
import Typography from '@mui/material/Typography';
import { makeStyles } from '@mui/styles';
import React, { useRef, useState } from 'react';
import { graphql, useFragment } from 'react-relay';
import Tooltip from '@mui/material/Tooltip';
import { SettingsMessagesLine_settingsMessage$data } from '@components/settings/settings_messages/__generated__/SettingsMessagesLine_settingsMessage.graphql';
import { Stack } from '@mui/material';
import { useFormatter } from '../../../../components/i18n';
import { DataColumns } from '../../../../components/list_lines';
import type { Theme } from '../../../../components/Theme';
import { generateBannerMessageColors } from '../../../../utils/Colors';
import { SettingsMessages_settingsMessages$key } from './__generated__/SettingsMessages_settingsMessages.graphql';
import SettingsMessageCreation from './SettingsMessageCreation';
import SettingsMessagesLines from './SettingsMessagesLines';
import ItemBoolean from '../../../../components/ItemBoolean';
import ColumnsLinesTitles from '../../../../components/ColumnsLinesTitles';
import FieldOrEmpty from '../../../../components/FieldOrEmpty';

// Deprecated - https://mui.com/system/styles/basics/
// Do not use it for new code.
const useStyles = makeStyles<Theme>(() => ({
  paper: {
    margin: 0,
    padding: '15px',
    borderRadius: 4,
    position: 'relative',
    listStyleType: 'none',
  },
}));

const settingsMessagesFragment = graphql`
  fragment SettingsMessages_settingsMessages on Settings {
    messages_administration {
      ...SettingsMessagesLine_settingsMessage
    }
  }
`;

const SettingsMessages = ({
  settings,
}: {
  settings: SettingsMessages_settingsMessages$key & { readonly id: string };
}) => {
  const { t_i18n } = useFormatter();
  const ref = useRef(null);
  const classes = useStyles();
  const messages = useFragment<SettingsMessages_settingsMessages$key>(
    settingsMessagesFragment,
    settings,
  )?.messages_administration ?? [];
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
            {t_i18n('Sample')}
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
            label={data.activated ? t_i18n('Enabled') : t_i18n('Disabled')}
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
            label={data.dismissible ? t_i18n('Yes') : t_i18n('No')}
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
        <FieldOrEmpty source={data.recipients}>
          <Tooltip title={data.recipients?.map(({ name }) => name).join(', ')}>
            <span>{data.recipients?.map(({ name }) => name).join(', ')}</span>
          </Tooltip>
        </FieldOrEmpty>
      ),
    },
  };
  const datas = messages.map((m) => ({ node: m }));
  const [displayCreate, setDisplayCreate] = useState(false);
  const handleOpenCreate = () => setDisplayCreate(true);
  const handleCloseCreate = () => setDisplayCreate(false);
  return (
    <>
      <Stack direction="row" alignItems="center">
        <Typography variant="h4" gutterBottom={true} sx={{ margin: 0 }}>
          {t_i18n('Platform announcement')}
        </Typography>
        <IconButton
          color="primary"
          aria-label="Add"
          onClick={handleOpenCreate}
          size="small"
        >
          <Add fontSize="small" />
        </IconButton>
      </Stack>

      <Paper
        ref={ref}
        classes={{ root: classes.paper }}
        className="paper-for-grid"
        variant="outlined"
        style={{ marginTop: 0 }}
      >
        <ColumnsLinesTitles
          dataColumns={dataColumns}
          secondaryAction={true}
        />
        <SettingsMessagesLines
          settingsId={settings.id}
          datas={datas}
          dataColumns={dataColumns}
          containerRef={ref}
        />
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
