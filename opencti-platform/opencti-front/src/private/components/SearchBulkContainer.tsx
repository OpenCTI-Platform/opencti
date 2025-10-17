import React, { ChangeEvent, MouseEvent, useState } from 'react';
import Grid from '@mui/material/Grid';
import TextField from '@mui/material/TextField';
import Box from '@mui/material/Box';
import Tabs from '@mui/material/Tabs';
import Tab from '@mui/material/Tab';
import { isEmpty } from 'ramda';
import Chip from '@mui/material/Chip';
import { useNavigate } from 'react-router-dom';
import { useTheme } from '@mui/material/styles';
import SearchBulkUnknownEntities from './SearchBulkUnknownEntities';
import { useFormatter } from '../../components/i18n';
import Breadcrumbs from '../../components/Breadcrumbs';
import useConnectedDocumentModifier from '../../utils/hooks/useConnectedDocumentModifier';
import SearchBulk, { BULK_SEARCH_LOCAL_STORAGE_KEY } from './SearchBulk';
import DataTableWithoutFragment from '../../components/dataGrid/DataTableWithoutFragment';
import { resolveLink } from '../../utils/Entity';
import { typesWithNoAnalysesTab } from '../../utils/hooks/useAttributes';
import { DataTableProps } from '../../components/dataGrid/dataTableTypes';

const SearchBulkContainer = () => {
  const { t_i18n, n } = useFormatter();
  const theme = useTheme();
  const navigate = useNavigate();
  const { setTitle } = useConnectedDocumentModifier();

  setTitle(t_i18n('Bulk Search'));

  const [textFieldValue, setTextFieldValue] = useState('');
  const [currentTab, setCurrentTab] = useState(0);
  const [numberOfUnknownEntities, setNumberOfUnknownEntities] = useState(0);

  const handleChangeTab = (value: number) => {
    setCurrentTab(value);
  };
  const values = textFieldValue
    .split('\n')
    .filter((o) => o.length > 1)
    .map((val) => val.trim()) ?? [];

  const handleChangeTextField = (event: ChangeEvent<HTMLInputElement>) => {
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

  const dataColumns: DataTableProps['dataColumns'] = {
    entity_type: {
      isSortable: true,
    },
    value: {
      isSortable: false,
    },
    createdBy: {},
    creators: {},
    objectLabel: {},
    created_at: {
      percentWidth: 14,
    },
    analyses: {
      percentWidth: 7,
      id: 'analyses',
      label: 'Analyses',
      isSortable: false,
      render: ({ id, entity_type, containersNumber }) => {
        const analysesNumber = containersNumber?.total;
        const link = `${resolveLink(entity_type)}/${id}`;
        const linkAnalyses = `${link}/analyses`;
        const analysesChipStyle: React.CSSProperties = {
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
                  sx={{
                    ...analysesChipStyle,
                    cursor: 'pointer',
                    '&:hover': {
                      backgroundColor: theme.palette.primary.main,
                    },
                  }}
                  label={n(analysesNumber)}
                  onClick={(e: MouseEvent<HTMLDivElement>) => {
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
      <Breadcrumbs elements={[{ label: t_i18n('Search') }, { label: t_i18n('Bulk search'), current: true }]} />
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
        <Grid item xs={10}>
          <Box sx={{ borderBottom: 1, borderColor: 'divider', marginBottom: 3, marginTop: -3 }}>
            <Tabs
              value={currentTab}
              onChange={(_, value) => handleChangeTab(value)}
            >
              <Tab label={t_i18n('Known entities')} />
              <Tab label={`${t_i18n('Unknown entities')} (${numberOfUnknownEntities})`} />
            </Tabs>
          </Box>
          {currentTab === 0 && values.length > 0
            && <SearchBulk inputValues={values} dataColumns={dataColumns} />
          }
          {currentTab === 0 && isEmpty(textFieldValue)
            && <DataTableWithoutFragment data={[]} globalCount={0} dataColumns={dataColumns} storageKey={BULK_SEARCH_LOCAL_STORAGE_KEY} />
          }
          <SearchBulkUnknownEntities
            values={values}
            setNumberOfEntities={setNumberOfUnknownEntities}
            isDisplayed={currentTab === 1}
          />
        </Grid>
      </Grid>
    </>
  );
};

export default SearchBulkContainer;
