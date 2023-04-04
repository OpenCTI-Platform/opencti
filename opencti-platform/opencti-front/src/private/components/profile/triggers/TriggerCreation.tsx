/* eslint-disable @typescript-eslint/no-unused-vars */
import React, { FunctionComponent, useState } from 'react';
import { BackupTableOutlined, CampaignOutlined } from '@mui/icons-material';
import SpeedDialIcon from '@mui/material/SpeedDialIcon';
import SpeedDialAction from '@mui/material/SpeedDialAction';
import SpeedDial from '@mui/material/SpeedDial';
import makeStyles from '@mui/styles/makeStyles';
import { Theme } from '../../../../components/Theme';
import { useFormatter } from '../../../../components/i18n';
import { TriggersLinesPaginationQuery$variables } from './__generated__/TriggersLinesPaginationQuery.graphql';
import { TriggerLiveCreationMutation$data } from './__generated__/TriggerLiveCreationMutation.graphql';
import TriggerDigestCreation from './TriggerDigestCreation';
import TriggerLiveCreation from './TriggerLiveCreation';
import Filters from '../../common/lists/Filters';
import { isUniqFilter } from '../../../../utils/filters/filtersUtils';
import SelectField from '../../../../components/SelectField';
import {
  TriggerCreationLiveMutation,
  TriggerCreationLiveMutation$data,
  TriggerEventType,
} from './__generated__/TriggerCreationLiveMutation.graphql';
import TriggersField from './TriggersField';
import TimePickerField from '../../../../components/TimePickerField';
import { dayStartDate, parse } from '../../../../utils/Time';
import FilterIconButton from '../../../../components/FilterIconButton';
import SwitchField from '../../../../components/SwitchField';
import FilterAutocomplete from '../../common/lists/FilterAutocomplete';
import AutocompleteField from '../../../../components/AutocompleteField';
import { fieldSpacingContainerStyle } from '../../../../utils/field';

const useStyles = makeStyles<Theme>((theme) => ({
  createButton: {
    position: 'fixed',
    bottom: 30,
    right: 30,
    zIndex: 1100,
  },
  speedDialButton: {
    backgroundColor: theme.palette.secondary.main,
    color: '#ffffff',
    '&:hover': {
      backgroundColor: theme.palette.secondary.main,
    },
  },
}));

interface TriggerCreationProps {
  contextual?: boolean;
  hideSpeedDial?: boolean;
  open?: boolean;
  handleClose?: () => void;
  inputValue?: string;
  paginationOptions?: TriggersLinesPaginationQuery$variables;
  creationCallback?: (data: TriggerLiveCreationMutation$data) => void;
}

const TriggerCreation: FunctionComponent<TriggerCreationProps> = ({
  contextual,
  hideSpeedDial,
  inputValue,
  paginationOptions,
  creationCallback,
  handleClose,
  open,
}) => {
  const { t } = useFormatter();
  const classes = useStyles();
  const [openSpeedDial, setOpenSpeedDial] = useState(false);
  // Live
  const [openLive, setOpenLive] = useState(false);
  const handleOpenCreateLive = () => {
    setOpenSpeedDial(false);
    setOpenLive(true);
  };
  // Digest
  const [openDigest, setOpenDigest] = useState(false);
  const handleOpenCreateDigest = () => {
    setOpenSpeedDial(false);
    setOpenDigest(true);
  };
  return (
    <>
      {hideSpeedDial !== true && (
        <SpeedDial
          className={classes.createButton}
          ariaLabel="Create"
          icon={<SpeedDialIcon />}
          onClose={() => setOpenSpeedDial(false)}
          onOpen={() => setOpenSpeedDial(true)}
          open={openSpeedDial}
          FabProps={{ color: 'secondary' }}
        >
          <SpeedDialAction
            title={t('Live trigger')}
            icon={<CampaignOutlined />}
            tooltipTitle={t('Create a live trigger')}
            onClick={handleOpenCreateLive}
            FabProps={{ classes: { root: classes.speedDialButton } }}
          />
          <SpeedDialAction
            title={t('Regular digest')}
            icon={<BackupTableOutlined />}
            tooltipTitle={t('Create a regular digest')}
            onClick={handleOpenCreateDigest}
            FabProps={{ classes: { root: classes.speedDialButton } }}
          />
        </SpeedDial>
      )}
      <TriggerLiveCreation
        contextual={contextual}
        inputValue={inputValue}
        paginationOptions={paginationOptions}
        open={open !== undefined ? open : openLive}
        handleClose={() => {
          if (handleClose) {
            handleClose();
          } else {
            setOpenLive(false);
          }
        }}
        creationCallback={creationCallback}
      />
      <TriggerDigestCreation
        contextual={contextual}
        inputValue={inputValue}
        paginationOptions={paginationOptions}
        open={openDigest}
        handleClose={() => setOpenDigest(false)}
      />
    </>
  );
};

export default TriggerCreation;
