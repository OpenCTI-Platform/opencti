import React, { useState } from 'react';
import Grid from '@mui/material/Grid';
import TextField from '@mui/material/TextField';
import Box from '@mui/material/Box';
import Tabs from '@mui/material/Tabs';
import Tab from '@mui/material/Tab';
import { useFormatter } from '../../components/i18n';
import Breadcrumbs from '../../components/Breadcrumbs';
import useConnectedDocumentModifier from '../../utils/hooks/useConnectedDocumentModifier';
import SearchBulk from './SearchBulk';

const SearchBulkContainer = () => {
  const { t_i18n } = useFormatter();
  const { setTitle } = useConnectedDocumentModifier();

  setTitle(t_i18n('Bulk Search'));

  const [textFieldValue, setTextFieldValue] = useState('');
  const [currentTab, setCurrentTab] = useState(0);
  const handleChangeTab = (value) => {
    setCurrentTab(value);
  };

  const handleChangeTextField = (event) => {
    const { value } = event.target;
    setTextFieldValue(
      value
        .split('\n')
        .map((o) => o
          .split(',')
          .map((p) => p.split(';'))
          .flat())
        .flat()
        .join('\n'),
    );
  };

  return (
    <>
      <Breadcrumbs variant="standard" elements={[{ label: t_i18n('Search') }, { label: t_i18n('Bulk search'), current: true }]} />
      <div className="clearfix" />
      <Grid
        container={true}
        spacing={3}
        style={{ marginBottom: 20, marginTop: 0 }}
      >
        <Grid item xs={2} style={{ marginTop: -20 }}>
          <TextField
            onChange={handleChangeTextField}
            value={textFieldValue}
            multiline={true}
            fullWidth={true}
            minRows={20}
            placeholder={t_i18n('One keyword by line or separated by commas')}
            variant="outlined"
          />
        </Grid>
          <Box sx={{ borderBottom: 1, borderColor: 'divider' }}>
            <Tabs
              value={currentTab}
              onChange={(event, value) => handleChangeTab(value)}
            >
              <Tab label={t_i18n('Known entities')} />
              <Tab label={t_i18n('Unknown entities')} />
            </Tabs>
          </Box>
          <Grid item xs={10}>
            {currentTab === 0 && <SearchBulk textFieldValue={textFieldValue} />}
          </Grid>
      </Grid>
    </>
  );
};

export default SearchBulkContainer;
