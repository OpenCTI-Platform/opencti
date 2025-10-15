import React, { useState } from 'react';
import Grid from '@mui/material/Grid';
import TextField from '@mui/material/TextField';
import Box from '@mui/material/Box';
import Tabs from '@mui/material/Tabs';
import Tab from '@mui/material/Tab';
import { isEmpty } from 'ramda';
import Chip from '@mui/material/Chip';
import { useNavigate } from 'react-router-dom';
import { useTheme } from '@mui/styles';
import { useFormatter } from '../../components/i18n';
import Breadcrumbs from '../../components/Breadcrumbs';
import useConnectedDocumentModifier from '../../utils/hooks/useConnectedDocumentModifier';
import SearchBulk from './SearchBulk';
import DataTableWithoutFragment from '../../components/dataGrid/DataTableWithoutFragment';
import { resolveLink } from '../../utils/Entity';
import { typesWithNoAnalysesTab } from '../../utils/hooks/useAttributes';

const SearchBulkContainer = () => {
  const { t_i18n, n } = useFormatter();
  const theme = useTheme();
  const navigate = useNavigate();
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

  const dataColumns = {
    entity_type: {
      isSortable: true,
    },
    value: {
      isSortable: true,
    },
    createdBy: {},
    creators: {},
    objectLabel: {},
    created_at: {},
    analyses: {
      id: 'analyses',
      label: 'Analyses',
      isSortable: false,
      render: ({ id, entity_type, containersNumber }) => {
        const analysesNumber = containersNumber?.total;
        const link = `${resolveLink(entity_type)}/${id}`;
        const linkAnalyses = `${link}/analyses`;
        const analysesChipStyle = {
          fontSize: 13,
          lineHeight: '12px',
          height: 20,
          textTransform: 'uppercase',
          borderRadius: 4,
        };
        return (
          <>
            {typesWithNoAnalysesTab.includes(entity_type)
              ? (<Chip
                  style={analysesChipStyle}
                  label={n(analysesNumber)}
                 />)
              : (<Chip
                  style={{
                    ...analysesChipStyle,
                    cursor: 'pointer',
                    '&:hover': {
                      backgroundColor: theme.palette.primary.main,
                    },
                  }}
                  label={n(analysesNumber)}
                  onClick={(e) => {
                    e.preventDefault();
                    e.stopPropagation();
                    navigate(linkAnalyses);
                  }}
                 />)
            }
          </>
        );
      },
    },
    objectMarking: {},
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
          {currentTab === 0 && textFieldValue.length > 0
            && <SearchBulk textFieldValue={textFieldValue} dataColumns={dataColumns} />
          }
          {currentTab === 0 && isEmpty(textFieldValue)
            && <DataTableWithoutFragment data={[]} globalCount={0} dataColumns={dataColumns} />
          }
        </Grid>
      </Grid>
    </>
  );
};

export default SearchBulkContainer;
