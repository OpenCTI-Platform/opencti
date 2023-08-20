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
import { graphql, createFragmentContainer } from 'react-relay';
import makeStyles from '@mui/styles/makeStyles';
import { useFormatter } from '../../../../components/i18n';
import PlaybookHeader from './PlaybookHeader';

const useStyles = makeStyles(() => ({
  container: {
    margin: 0,
  },
  gridContainer: {
    marginBottom: 20,
  },
}));

const PlaybookComponent = ({ playbook }) => {
  const classes = useStyles();
  const { t } = useFormatter();
  return (
    <div className={classes.container}>
      <PlaybookHeader playbook={playbook} />
      My super playbook!
    </div>
  );
};

const Playbook = createFragmentContainer(PlaybookComponent, {
  playbook: graphql`
    fragment Playbook_playbook on Playbook {
      id
      entity_type
      name
      description
      playbook_definition
      playbook_running
    }
  `,
});

export default Playbook;
