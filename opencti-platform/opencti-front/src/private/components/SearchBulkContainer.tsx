import React, { ChangeEvent, useEffect, useState } from 'react';
import Grid from '@mui/material/Grid';
import { isEmpty } from 'ramda';
import { useSearchParams } from 'react-router-dom';
import SearchBulkUnknownEntities from './SearchBulkUnknownEntities';
import { useFormatter } from '../../components/i18n';
import Breadcrumbs from '../../components/Breadcrumbs';
import useConnectedDocumentModifier from '../../utils/hooks/useConnectedDocumentModifier';
import SearchBulk, { BULK_SEARCH_LOCAL_STORAGE_KEY } from './SearchBulk';
import DataTableWithoutFragment from '../../components/dataGrid/DataTableWithoutFragment';
import { DataTableProps } from '../../components/dataGrid/dataTableTypes';
import useDebounceCallback from '../../utils/hooks/useDebounceCallback';
import { splitIntoLines } from '../../utils/String';
import { Tabs, TabsContent, TabsList, TabsTrigger, Textarea } from '@filigran/design-system';

const SearchBulkContainer = () => {
  const { t_i18n } = useFormatter();
  const { setTitle } = useConnectedDocumentModifier();
  const [searchParams, setSearchParams] = useSearchParams();

  setTitle(t_i18n('Bulk Search'));

  const [textFieldValue, setTextFieldValue] = useState('');
  const [currentTab, setCurrentTab] = useState('known');
  const [values, setValues] = useState<string[]>([]);
  const [numberOfUnknownEntities, setNumberOfUnknownEntities] = useState(0);
  const [numberOfKnownEntities, setNumberOfKnownEntities] = useState(0);

  const setValuesAfterDebounce = useDebounceCallback(setValues, 500); // set values with a 500ms debounce

  const bulkTextToValues = (text: string) => {
    return text
      .split('\n')
      .filter((o) => o.length > 1)
      .map((val) => val.trim()) ?? [];
  };

  // Pre-fill from ?q= query parameter (e.g. when coming from the top bar search)
  useEffect(() => {
    const q = searchParams.get('q');
    if (q) {
      const text = splitIntoLines(q);
      setTextFieldValue(text);
      setValues(bulkTextToValues(text));
      // Clean up the query param so it doesn't persist on refresh
      searchParams.delete('q');
      setSearchParams(searchParams, { replace: true });
    }
  }, [searchParams]);

  const handleChangeTab = (value: string) => {
    setCurrentTab(value);
  };

  const handleChangeTextField = (event: ChangeEvent<HTMLTextAreaElement>) => {
    const { value } = event.target;
    const text = splitIntoLines(value);
    setTextFieldValue(text);
    setValuesAfterDebounce(bulkTextToValues(text));
  };

  const dataColumns: DataTableProps['dataColumns'] = {
    entity_type: {
      isSortable: true,
    },
    value: {
      isSortable: false,
    },
    createdBy: {},
    creator: {},
    objectLabel: {},
    created_at: {
      percentWidth: 14,
    },
    analyses: {
      percentWidth: 7,
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
          <Textarea
            onChange={handleChangeTextField}
            value={textFieldValue}
            minRows={20}
            placeholder={t_i18n('One keyword by line or separated by commas')}
            resize="none"
          />
        </Grid>
        <Grid item xs={10}>
          <Tabs value={currentTab} onValueChange={handleChangeTab}>
            {/* -24px: inline, the negative utility is absent from the shipped CSS */}
            <div style={{ marginTop: -24 }}>
              <TabsList className="mb-6">
                <TabsTrigger value="known" badge={numberOfKnownEntities}>{t_i18n('Known entities')}</TabsTrigger>
                <TabsTrigger value="unknown" badge={numberOfUnknownEntities}>{t_i18n('Unknown entities')}</TabsTrigger>
              </TabsList>
            </div>
            <TabsContent value="known">
              {values.length > 0 && (
                <SearchBulk
                  inputValues={values}
                  dataColumns={dataColumns}
                  setNumberOfEntities={setNumberOfKnownEntities}
                />
              )}
              {isEmpty(textFieldValue)
                && <DataTableWithoutFragment data={[]} globalCount={0} dataColumns={dataColumns} storageKey={BULK_SEARCH_LOCAL_STORAGE_KEY} />}
            </TabsContent>
            {/* forceMount: this panel's query feeds the tab-label count, so it
                must stay mounted while inactive; isDisplayed gates the table. */}
            <TabsContent value="unknown" forceMount hidden={currentTab !== 'unknown'}>
              <SearchBulkUnknownEntities
                values={values}
                setNumberOfEntities={setNumberOfUnknownEntities}
                isDisplayed={currentTab === 'unknown'}
              />
            </TabsContent>
          </Tabs>
        </Grid>
      </Grid>
    </>
  );
};

export default SearchBulkContainer;
