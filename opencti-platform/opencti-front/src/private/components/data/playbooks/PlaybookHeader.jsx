/*
Copyright (c) 2021-2023 Filigran SAS

This file is part of the OpenCTI Enterprise Edition ("EE") and is
licensed under the OpenCTI Non-Commercial License (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

https://github.com/OpenCTI-Platform/opencti/blob/master/LICENSE

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
*/

import React from 'react';
import makeStyles from '@mui/styles/makeStyles';
import Typography from '@mui/material/Typography';
import Chip from '@mui/material/Chip';
import PlaybookPopover from './PlaybookPopover';
import { useFormatter } from '../../../../components/i18n';

const useStyles = makeStyles(() => ({
  title: {
    float: 'left',
    textTransform: 'uppercase',
  },
  popover: {
    float: 'left',
    marginTop: '-13px',
  },
  status: {
    float: 'right',
    marginTop: '-5px',
  },
  chip: {
    fontSize: 12,
    lineHeight: '12px',
    height: 25,
    textTransform: 'uppercase',
    borderRadius: '0',
  },
}));

const inlineStyles = {
  green: {
    backgroundColor: 'rgba(76, 175, 80, 0.08)',
    color: '#4caf50',
  },
  red: {
    backgroundColor: 'rgba(244, 67, 54, 0.08)',
    color: '#f44336',
  },
};

const PlaybookHeader = ({ playbook }) => {
  const classes = useStyles();
  const { t } = useFormatter();
  return (
    <>
      <Typography
        variant="h1"
        gutterBottom={true}
        classes={{ root: classes.title }}
      >
        {playbook.name}
      </Typography>
      <div className={classes.popover}>
        <PlaybookPopover
          playbookId={playbook.id}
          running={playbook.playbook_running}
        />
      </div>
      <div className={classes.status}>
        <Chip
          classes={{ root: classes.chip }}
          style={
            playbook.playbook_running ? inlineStyles.green : inlineStyles.red
          }
          label={
            playbook.playbook_running
              ? t('Playbook is running')
              : t('Playbook is stopped')
          }
        />
      </div>
      <div className="clearfix" />
    </>
  );
};

export default PlaybookHeader;
