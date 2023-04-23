import React from 'react';
import makeStyles from '@mui/styles/makeStyles';
import ActivityMenu from '../../ActivityMenu';
import { Theme } from '../../../../../components/Theme';

// ------------------------------------------------------------------------ //
//     OpenCTI Enterprise Edition License                                   //
// ------------------------------------------------------------------------ //
//     Copyright (c) 2021-2023 Filigran SAS                                 //
//                                                                          //
// This file is part of the OpenCTI Enterprise Edition ("EE") and is        //
// licensed under the OpenCTI Non-Commercial License (the "License");       //
// you may not use this file except in compliance with the License.         //
// You may obtain a copy of the License at                                  //
//                                                                          //
// https://github.com/OpenCTI-Platform/opencti/blob/master/LICENSE          //
//                                                                          //
// Unless required by applicable law or agreed to in writing, software      //
// distributed under the License is distributed on an "AS IS" BASIS,        //
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. //
// ------------------------------------------------------------------------ //

const useStyles = makeStyles<Theme>((theme) => ({
  container: {
    margin: 0,
    padding: '0 200px 0 0',
  },
  gridContainer: {
    marginBottom: 20,
  },
  title: {
    float: 'left',
    textTransform: 'uppercase',
  },
  popover: {
    float: 'left',
    marginTop: '-13px',
  },
  paper: {
    height: '100%',
    minHeight: '100%',
    margin: '10px 0 0 0',
    padding: '15px',
    borderRadius: 6,
  },
  editButton: {
    position: 'fixed',
    bottom: 30,
    right: 230,
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

const Statistics = () => {
  const classes = useStyles();
  return (
      <div className={classes.container}>
        <ActivityMenu />
      </div>
  );
};

export default Statistics;
