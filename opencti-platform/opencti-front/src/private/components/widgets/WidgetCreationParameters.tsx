import TextField from '@mui/material/TextField';
import InputLabel from '@mui/material/InputLabel';
import ReactMde from 'react-mde';
import FormControl from '@mui/material/FormControl';
import Select from '@mui/material/Select';
import MenuItem from '@mui/material/MenuItem';
import { stixCyberObservablesLinesAttributesQuery } from '@components/observations/stix_cyber_observables/StixCyberObservablesLines';
import * as R from 'ramda';
import FormControlLabel from '@mui/material/FormControlLabel';
import Switch from '@mui/material/Switch';
import Tooltip from '@mui/material/Tooltip';
import { InformationOutline } from 'mdi-material-ui';
import React, { FunctionComponent, useState } from 'react';
import { StixCyberObservablesLinesAttributesQuery$data } from '@components/observations/stix_cyber_observables/__generated__/StixCyberObservablesLinesAttributesQuery.graphql';
import WidgetConfigColumnsCustomization from '@components/workspaces/dashboards/WidgetConfigColumnsCustomization';
import { commonWidgetColumns, defaultWidgetColumns } from '@components/widgets/WidgetListsDefaultColumns';
import { getCurrentAvailableParameters, getCurrentCategory, getCurrentIsRelationships, isWidgetListOrTimeline } from './widgetUtils';
import { QueryRenderer } from '../../../relay/environment';
import { isNotEmptyField } from '../../../utils/utils';
import { capitalizeFirstLetter } from '../../../utils/String';
import MarkdownDisplay from '../../../components/MarkdownDisplay';
import { useFormatter } from '../../../components/i18n';
import { findFiltersFromKeys } from '../../../utils/filters/filtersUtils';
import useAttributes from '../../../utils/hooks/useAttributes';
import type { WidgetColumn, WidgetDataSelection, WidgetParameters } from '../../../utils/widget/widget';
import useHelper from '../../../utils/hooks/useHelper';

interface WidgetCreationParametersProps {
  dataSelection: WidgetDataSelection[],
  setDataSelection: (d: WidgetDataSelection[] | ((prevDataSelection: WidgetDataSelection[]) => WidgetDataSelection[])) => void,
  parameters: WidgetParameters,
  setParameters: (p: WidgetParameters) => void,
  type: string,
}

const WidgetCreationParameters: FunctionComponent<WidgetCreationParametersProps> = ({
  dataSelection,
  setDataSelection,
  parameters,
  setParameters,
  type,
}) => {
  const { t_i18n } = useFormatter();
  const { isFeatureEnable } = useHelper();
  const { ignoredAttributesInDashboards } = useAttributes();
  const [selectedTab, setSelectedTab] = useState<'write' | 'preview' | undefined>('write');
  const handleChangeDataValidationParameter = (
    i: number,
    key: string,
    value: string | null,
    number = false,
  ) => {
    if (value === null) {
      throw Error(t_i18n('This value cannot be null'));
    }
    const newDataSelection = dataSelection.map((data, n) => {
      if (n === i) {
        return {
          ...data,
          [key]: number ? parseInt(value, 10) : value,
        };
      }
      return data;
    });
    setDataSelection(newDataSelection);
  };
  const handleToggleDataValidationIsTo = (i: number) => {
    const newDataSelection = dataSelection.map((data, n) => {
      if (n === i) {
        return { ...data, isTo: !data.isTo };
      }
      return data;
    });
    setDataSelection(newDataSelection);
  };
  const handleToggleParameter = (parameter: keyof WidgetParameters) => {
    setParameters({ ...parameters, [parameter]: !parameters[parameter] });
  };
  const handleChangeParameter = (parameter: string, value: string) => {
    setParameters({ ...parameters, [parameter]: value });
  };

  const getCurrentSelectedEntityTypes = (index: number) => {
    return R.uniq(
      findFiltersFromKeys(dataSelection[index]?.filters?.filters ?? [], [
        'fromTypes',
        'toTypes',
        'entity_type',
      ])
        .map((f) => f.values)
        .flat(),
    );
  };

  const setColumns = (index: number, newColumns: WidgetColumn[]) => {
    setDataSelection((prevDataSelection) => {
      return prevDataSelection.map((selection, i) => (i === index ? { ...selection, columns: newColumns } : selection));
    });
  };

  return (
    <div style={{ marginTop: 20 }}>
      <TextField
        label={t_i18n('Title')}
        fullWidth={true}
        value={parameters.title}
        onChange={(event) => handleChangeParameter('title', event.target.value)
        }
      />
      {getCurrentCategory(type) === 'text' && (
        <div style={{ marginTop: 20 }}>
          <InputLabel shrink={true}>{t_i18n('Content')}</InputLabel>
          <ReactMde
            value={parameters.content ?? undefined}
            onChange={(value) => handleChangeParameter('content', value)}
            selectedTab={selectedTab}
            onTabChange={(tab) => setSelectedTab(tab)}
            generateMarkdownPreview={(markdown) => Promise.resolve(
              <MarkdownDisplay
                content={markdown}
                remarkGfmPlugin={true}
                commonmark={true}
              />,
            )}
            l18n={{
              write: t_i18n('Write'),
              preview: t_i18n('Preview'),
              uploadingImage: t_i18n('Uploading image'),
              pasteDropSelect: t_i18n('Paste'),
            }}
            minEditorHeight={100}
            maxEditorHeight={100}
          />
        </div>
      )}
      {getCurrentCategory(type) === 'timeseries' && (
        <FormControl fullWidth={true} style={{ marginTop: 20 }}>
          <InputLabel id="relative">{t_i18n('Interval')}</InputLabel>
          <Select
            labelId="relative"
            fullWidth={true}
            value={parameters.interval ?? 'day'}
            onChange={(event) => handleChangeParameter('interval', event.target.value)
            }
          >
            <MenuItem value="day">{t_i18n('Day')}</MenuItem>
            <MenuItem value="week">{t_i18n('Week')}</MenuItem>
            <MenuItem value="month">{t_i18n('Month')}</MenuItem>
            <MenuItem value="quarter">{t_i18n('Quarter')}</MenuItem>
            <MenuItem value="year">{t_i18n('Year')}</MenuItem>
          </Select>
        </FormControl>
      )}
      <>
        {Array(dataSelection.length)
          .fill(0)
          .map((_, i) => {
            return (
              <div key={i}>
                {(getCurrentCategory(type) === 'distribution'
                  || getCurrentCategory(type) === 'list') && (
                  <TextField
                    label={t_i18n('Number of results')}
                    fullWidth={true}
                    type="number"
                    value={dataSelection[i].number ?? 10}
                    onChange={(event) => handleChangeDataValidationParameter(
                      i,
                      'number',
                      event.target.value,
                      true,
                    )
                    }
                    style={{ marginTop: 20 }}
                  />
                )}
                {getCurrentCategory(type) === 'list' && dataSelection[i].perspective === 'entities' && (
                  <div
                    style={{
                      display: 'flex',
                      width: '100%',
                      marginTop: 20,
                    }}
                  >
                    <FormControl
                      style={{ width: '100%', flex: 1 }}
                      fullWidth={true}
                    >
                      <InputLabel>{t_i18n('Sort by')}</InputLabel>
                      <Select
                        fullWidth={true}
                        value={dataSelection[i].sort_by ?? 'created_at'}
                        onChange={(event) => handleChangeDataValidationParameter(
                          i,
                          'sort_by',
                          event.target.value,
                        )
                        }
                      >
                        {[
                          'created',
                          'created_at',
                          'modified',
                          'updated_at',
                          'name',
                          'valid_from',
                          'valid_until',
                          'entity_type',
                          'createdBy',
                          'creator',
                          'objectMarking',
                          'observable_value',
                          'value',
                          'x_opencti_workflow_id',
                          'opinions_metrics_mean',
                          'opinions_metrics_max',
                          'opinions_metrics_min',
                          'opinions_metrics_total',
                        ].map((value) => (
                          <MenuItem
                            key={value}
                            value={value}
                          >
                            {t_i18n(capitalizeFirstLetter(value))}
                          </MenuItem>
                        ))}
                      </Select>
                    </FormControl>
                  </div>
                )}
                {getCurrentCategory(type) === 'list' && (
                  <div
                    style={{
                      display: 'flex',
                      width: '100%',
                      marginTop: 20,
                    }}
                  >
                    <FormControl fullWidth={true} style={{ flex: 1 }}>
                      <InputLabel id="relative" size="small">
                        {t_i18n('Sort mode')}
                      </InputLabel>
                      <Select
                        labelId="relative"
                        size="small"
                        fullWidth={true}
                        value={dataSelection[i].sort_mode ?? 'asc'}
                        onChange={(event) => handleChangeDataValidationParameter(i, 'sort_mode', event.target.value)}
                      >
                        <MenuItem value="asc">
                          {t_i18n('Asc')}
                        </MenuItem>
                        <MenuItem value="desc">
                          {t_i18n('Desc')}
                        </MenuItem>
                      </Select>
                    </FormControl>
                  </div>
                )}
                {dataSelection[i].perspective !== 'audits' && (
                  <div
                    style={{
                      display: 'flex',
                      width: '100%',
                      marginTop: 20,
                    }}
                  >
                    <FormControl fullWidth={true} style={{ flex: 1 }}>
                      <InputLabel id="relative" size="small">
                        {isNotEmptyField(dataSelection[i].label)
                          ? dataSelection[i].label
                          : t_i18n('Date attribute')}
                      </InputLabel>
                      <Select
                        labelId="relative"
                        size="small"
                        fullWidth={true}
                        value={dataSelection[i].date_attribute ?? 'created_at'}
                        onChange={(event) => handleChangeDataValidationParameter(i, 'date_attribute', event.target.value)}
                      >
                        <MenuItem value="created_at">
                          created_at ({t_i18n('Technical date')})
                        </MenuItem>
                        <MenuItem value="updated_at">
                          updated_at ({t_i18n('Technical date')})
                        </MenuItem>
                        <MenuItem value="created">
                          created ({t_i18n('Functional date')})
                        </MenuItem>
                        <MenuItem value="modified">
                          modified ({t_i18n('Functional date')})
                        </MenuItem>
                        {getCurrentIsRelationships(type) && (
                          <MenuItem value="start_time">
                            start_time ({t_i18n('Functional date')})
                          </MenuItem>
                        )}
                        {getCurrentIsRelationships(type) && (
                          <MenuItem value="stop_time">
                            stop_time ({t_i18n('Functional date')})
                          </MenuItem>
                        )}
                        {getCurrentIsRelationships(type) && !isWidgetListOrTimeline(type) && (
                          <MenuItem value="first_seen">
                            first_seen ({t_i18n('Functional date')})
                          </MenuItem>
                        )}
                        {getCurrentIsRelationships(type) && !isWidgetListOrTimeline(type) && (
                          <MenuItem value="last_seen">
                            last_seen ({t_i18n('Functional date')})
                          </MenuItem>
                        )}
                      </Select>
                    </FormControl>
                  </div>
                )}
                {dataSelection[i].perspective === 'relationships'
                  && type === 'map' && (
                    <TextField
                      label={t_i18n('Zoom')}
                      fullWidth={true}
                      value={dataSelection[i].zoom ?? 2}
                      placeholder={t_i18n('Zoom')}
                      onChange={(event) => handleChangeDataValidationParameter(
                        i,
                        'zoom',
                        event.target.value,
                      )
                      }
                      style={{ marginTop: 20 }}
                    />
                )}
                {dataSelection[i].perspective === 'relationships'
                  && type === 'map' && (
                    <TextField
                      label={t_i18n('Center latitude')}
                      fullWidth={true}
                      value={dataSelection[i].centerLat ?? 48.8566969}
                      placeholder={t_i18n('Center latitude')}
                      onChange={(event) => handleChangeDataValidationParameter(
                        i,
                        'centerLat',
                        event.target.value,
                      )
                      }
                      style={{ marginTop: 20 }}
                    />
                )}
                {dataSelection[i].perspective === 'relationships'
                  && type === 'map' && (
                    <TextField
                      label={t_i18n('Center longitude')}
                      fullWidth={true}
                      value={dataSelection[i].centerLng ?? 2.3514616}
                      placeholder={t_i18n('Center longitude')}
                      onChange={(event) => handleChangeDataValidationParameter(
                        i,
                        'centerLng',
                        event.target.value,
                      )
                      }
                      style={{ marginTop: 20 }}
                    />
                )}
                {getCurrentAvailableParameters(type).includes('attribute') && (
                  <div
                    style={{ display: 'flex', width: '100%', marginTop: 20 }}
                  >
                    {dataSelection[i].perspective === 'relationships' && (
                      <FormControl
                        fullWidth={true}
                        style={{
                          flex: 1,
                          marginRight: 20,
                          width: '100%',
                        }}
                      >
                        <InputLabel>{t_i18n('Attribute')}</InputLabel>
                        <Select
                          fullWidth={true}
                          value={dataSelection[i].attribute}
                          onChange={(event) => handleChangeDataValidationParameter(
                            i,
                            'attribute',
                            event.target.value,
                          )
                          }
                        >
                          <MenuItem key="internal_id" value="internal_id">
                            {t_i18n('Entity')}
                          </MenuItem>
                          <MenuItem key="entity_type" value="entity_type">
                            {t_i18n('Entity type')}
                          </MenuItem>
                          <MenuItem key="relationship_type" value="relationship_type">
                            {t_i18n('Relationship type')}
                          </MenuItem>
                          <MenuItem
                            key="created-by.internal_id"
                            value="created-by.internal_id"
                          >
                            {t_i18n('Author')}
                          </MenuItem>
                          <MenuItem
                            key="object-marking.internal_id"
                            value="object-marking.internal_id"
                          >
                            {t_i18n('Marking definition')}
                          </MenuItem>
                          <MenuItem
                            key="kill-chain-phase.internal_id"
                            value="kill-chain-phase.internal_id"
                          >
                            {t_i18n('Kill chain phase')}
                          </MenuItem>
                          <MenuItem key="creator_id" value="creator_id">
                            {t_i18n('Creator')}
                          </MenuItem>
                          <MenuItem key="x_opencti_workflow_id" value="x_opencti_workflow_id">
                            {t_i18n('Status')}
                          </MenuItem>
                        </Select>
                      </FormControl>
                    )}
                    {dataSelection[i].perspective === 'entities'
                      && getCurrentSelectedEntityTypes(i).length > 0
                      && (
                        <FormControl
                          fullWidth={true}
                          style={{
                            flex: 1,
                            width: '100%',
                          }}
                        >
                          <InputLabel>{t_i18n('Attribute')}</InputLabel>
                          <QueryRenderer
                            query={stixCyberObservablesLinesAttributesQuery}
                            variables={{
                              elementType: getCurrentSelectedEntityTypes(i),
                            }}
                            render={({ props: resultProps }: { props: StixCyberObservablesLinesAttributesQuery$data }) => {
                              if (resultProps
                                && resultProps.schemaAttributeNames
                              ) {
                                let attributesValues = (resultProps.schemaAttributeNames.edges)
                                  .map((n) => n.node.value)
                                  .filter(
                                    (n) => !R.includes(
                                      n,
                                      ignoredAttributesInDashboards,
                                    ) && !n.startsWith('i_'),
                                  );
                                if (
                                  attributesValues.filter((n) => n === 'hashes').length > 0
                                ) {
                                  attributesValues = [
                                    ...attributesValues,
                                    'hashes.MD5',
                                    'hashes.SHA-1',
                                    'hashes.SHA-256',
                                    'hashes.SHA-512',
                                  ].filter((n) => n !== 'hashes').sort();
                                }
                                return (
                                  <Select
                                    fullWidth={true}
                                    value={dataSelection[i].attribute}
                                    onChange={(event) => handleChangeDataValidationParameter(
                                      i,
                                      'attribute',
                                      event.target.value,
                                    )
                                    }
                                  >
                                    {[
                                      ...attributesValues,
                                      'created-by.internal_id',
                                      'object-label.internal_id',
                                      'object-assignee.internal_id',
                                      'object-marking.internal_id',
                                      'kill-chain-phase.internal_id',
                                      'x_opencti_workflow_id',
                                    ].map((value) => (
                                      <MenuItem
                                        key={value}
                                        value={value}
                                      >
                                        {t_i18n(
                                          capitalizeFirstLetter(
                                            value,
                                          ),
                                        )}
                                      </MenuItem>
                                    ))}
                                  </Select>
                                );
                              }
                              return <div/>;
                            }}
                          />
                        </FormControl>
                      )}
                    {dataSelection[i].perspective === 'entities'
                      && getCurrentSelectedEntityTypes(i).length === 0 && (
                        <FormControl
                          fullWidth={true}
                          style={{
                            flex: 1,
                            marginRight: 20,
                            width: '100%',
                          }}
                        >
                          <InputLabel>{t_i18n('Attribute')}</InputLabel>
                          <Select
                            fullWidth={true}
                            value={dataSelection[i].attribute ?? 'entity_type'}
                            onChange={(event) => handleChangeDataValidationParameter(
                              i,
                              'attribute',
                              event.target.value,
                            )
                            }
                          >
                            {[
                              'entity_type',
                              'created-by.internal_id',
                              'object-label.internal_id',
                              'object-assignee.internal_id',
                              'object-marking.internal_id',
                              'kill-chain-phase.internal_id',
                              'x_opencti_workflow_id',
                            ].map((value) => (
                              <MenuItem
                                key={value}
                                value={value}
                              >
                                {t_i18n(capitalizeFirstLetter(value))}
                              </MenuItem>
                            ))}
                          </Select>
                        </FormControl>
                    )}
                    {dataSelection[i].perspective === 'audits' && (
                      <FormControl
                        fullWidth={true}
                        style={{
                          flex: 1,
                          width: '100%',
                        }}
                      >
                        <InputLabel>{t_i18n('Attribute')}</InputLabel>
                        <Select
                          fullWidth={true}
                          value={dataSelection[i].attribute ?? 'entity_type'}
                          onChange={(event) => handleChangeDataValidationParameter(
                            i,
                            'attribute',
                            event.target.value,
                          )
                          }
                        >
                          {['entity_type',
                            'context_data.id',
                            'context_data.created_by_ref_id',
                            'context_data.labels_ids',
                            'context_data.object_marking_refs_ids',
                            'context_data.creator_ids',
                            'context_data.search',
                            'event_type',
                            'event_scope',
                            'user_id',
                            'group_ids',
                            'organization_ids',
                          ].map((value) => (
                            <MenuItem
                              key={value}
                              value={value}
                            >
                              {t_i18n(capitalizeFirstLetter(value))}
                            </MenuItem>
                          ))}
                        </Select>
                      </FormControl>
                    )}
                    {dataSelection[i].perspective === 'relationships' && (
                      <FormControlLabel
                        control={
                          <Switch
                            onChange={() => handleToggleDataValidationIsTo(i)}
                            checked={!dataSelection[i].isTo}
                          />
                        }
                        label={t_i18n('Display the source')}
                      />
                    )}
                    {dataSelection[i].perspective === 'relationships' && (
                      <Tooltip
                        title={t_i18n(
                          'Enable if the displayed data is the source of the relationships.',
                        )}
                      >
                        <InformationOutline
                          fontSize="small"
                          color="primary"
                          style={{ marginTop: 14 }}
                        />
                      </Tooltip>
                    )}
                    TOTO
                  </div>
                )}
              </div>
            );
          })}
      </>
      <div style={{ display: 'flex', width: '100%', marginTop: 20 }}>
        {getCurrentAvailableParameters(type).includes('stacked') && (
          <FormControlLabel
            control={
              <Switch
                onChange={() => handleToggleParameter('stacked')}
                checked={parameters.stacked ?? undefined}
              />
            }
            label={t_i18n('Stacked')}
          />
        )}
        {getCurrentAvailableParameters(type).includes('distributed') && (
          <FormControlLabel
            control={
              <Switch
                onChange={() => handleToggleParameter('distributed')}
                checked={parameters.distributed ?? undefined}
              />
            }
            label={t_i18n('Distributed')}
          />
        )}
        {getCurrentAvailableParameters(type).includes('legend') && (
          <FormControlLabel
            control={
              <Switch
                onChange={() => handleToggleParameter('legend')}
                checked={parameters.legend ?? undefined}
              />
            }
            label={t_i18n('Display legend')}
          />
        )}
        {isFeatureEnable('COLUMNS_CUSTOMIZATION') && getCurrentCategory(type) === 'list'
          && dataSelection.map(({ perspective, columns }, index) => ((perspective === 'relationships') ? (
            <WidgetConfigColumnsCustomization
              key={index}
              availableColumns={commonWidgetColumns[perspective]}
              defaultColumns={defaultWidgetColumns[perspective]}
              columns={[...(columns ?? defaultWidgetColumns[perspective])]}
              setColumns={(newColumns) => setColumns(index, newColumns)}
            />
          ) : null))}
      </div>
    </div>
  );
};

export default WidgetCreationParameters;
