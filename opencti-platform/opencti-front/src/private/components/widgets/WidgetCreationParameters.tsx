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
import InputAdornment from '@mui/material/InputAdornment';
import { InformationOutline } from 'mdi-material-ui';
import React, { useState } from 'react';
import { StixCyberObservablesLinesAttributesQuery$data } from '@components/observations/stix_cyber_observables/__generated__/StixCyberObservablesLinesAttributesQuery.graphql';
import WidgetColumnsCustomizationInput from '@components/widgets/WidgetColumnsCustomizationInput';
import { getDefaultWidgetColumns, getWidgetColumns } from '@components/widgets/WidgetListsDefaultColumns';
import { useWidgetConfigContext } from '@components/widgets/WidgetConfigContext';
import useWidgetConfigValidateForm from '@components/widgets/useWidgetConfigValidateForm';
import WidgetAttributesInputContainer, { widgetAttributesInputInstanceQuery } from '@components/widgets/WidgetAttributesInputContainer';
import { WidgetAttributesInputContainerInstanceQuery$data } from '@components/widgets/__generated__/WidgetAttributesInputContainerInstanceQuery.graphql';
import { QueryRenderer } from '../../../relay/environment';
import { isNotEmptyField } from '../../../utils/utils';
import { capitalizeFirstLetter } from '../../../utils/String';
import MarkdownDisplay from '../../../components/MarkdownDisplay';
import { useFormatter } from '../../../components/i18n';
import { findFiltersFromKeys, getEntityTypeTwoFirstLevelsFilterValues, SELF_ID, SELF_ID_VALUE } from '../../../utils/filters/filtersUtils';
import useAttributes from '../../../utils/hooks/useAttributes';
import type { WidgetColumn, WidgetParameters } from '../../../utils/widget/widget';
import { getCurrentAvailableParameters, getCurrentCategory, getCurrentIsRelationships, isWidgetListOrTimeline } from '../../../utils/widget/widgetUtils';
import EntitySelectWithTypes from '../../../components/fields/EntitySelectWithTypes';
import { FilterGroup } from '../../../utils/filters/filtersHelpers-types';
import useAuth from '../../../utils/hooks/useAuth';

const WidgetCreationParameters = () => {
  const { t_i18n } = useFormatter();
  const {
    platformModuleHelpers: { isRuntimeFieldEnable },
  } = useAuth();
  const { ignoredAttributesInDashboards } = useAttributes();
  const [selectedTab, setSelectedTab] = useState<'write' | 'preview' | undefined>('write');

  const isRuntimeSort = isRuntimeFieldEnable() ?? false;
  const runtimeSortByValues = isRuntimeSort ? [ // values sortable only if runtime mapping is enabled
    'createdBy',
    'creator',
    'objectMarking',
    'observable_value',
  ] : [];
  const sortByValues = [
    'created',
    'created_at',
    'modified',
    'updated_at',
    'name',
    'valid_from',
    'valid_until',
    'entity_type',
    ...runtimeSortByValues,
    'value',
    'x_opencti_workflow_id',
    'opinions_metrics_mean',
    'opinions_metrics_max',
    'opinions_metrics_min',
    'opinions_metrics_total',
  ];

  const {
    config,
    setConfigWidget,
    context,
    setConfigVariableName,
    setDataSelectionWithIndex,
    fintelWidgets,
  } = useWidgetConfigContext();
  const { type, dataSelection, parameters } = config.widget;
  const { isWidgetVarNameAlreadyUsed, isVariableNameValid } = useWidgetConfigValidateForm();

  const alreadyUsedInstances = (fintelWidgets ?? []).flatMap(({ widget }) => {
    if (widget.type !== 'attribute') return [];
    return widget.dataSelection[0].instance_id ?? [];
  });

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
    setConfigWidget({ ...config.widget, dataSelection: newDataSelection });
  };

  const handleChangeDataValidationColumns = (
    i: number,
    value: WidgetColumn[],
  ) => {
    if (value === null) {
      throw Error(t_i18n('This value cannot be null'));
    }
    const newDataSelection = dataSelection.map((data, n) => {
      if (n === i) {
        return {
          ...data,
          columns: value.map((v) => ({ ...v, variableName: v.variableName ?? v.attribute })),
        };
      }
      return data;
    });
    setConfigWidget({ ...config.widget, dataSelection: newDataSelection });
  };

  const handleToggleDataValidationIsTo = (i: number) => {
    const newDataSelection = dataSelection.map((data, n) => {
      if (n === i) {
        return { ...data, isTo: !data.isTo };
      }
      return data;
    });
    setConfigWidget({ ...config.widget, dataSelection: newDataSelection });
  };

  const handleToggleParameter = (parameter: keyof WidgetParameters) => {
    setConfigWidget({
      ...config.widget,
      parameters: {
        ...config.widget.parameters,
        [parameter]: !parameters[parameter],
      },
    });
  };

  const handleChangeParameter = (parameter: string, value: string) => {
    setConfigWidget({
      ...config.widget,
      parameters: {
        ...config.widget.parameters,
        [parameter]: value,
      },
    });
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
    const prevSelection = dataSelection[index];
    const newSelection = { ...prevSelection, columns: newColumns };
    setDataSelectionWithIndex(newSelection, index);
  };

  let varNameError = '';
  if (isWidgetVarNameAlreadyUsed) {
    varNameError = t_i18n('This name is already used for an other widget');
  } else if (!isVariableNameValid) {
    varNameError = t_i18n('Only letters, numbers and special chars _ and - are allowed');
  }

  return (
    <div style={{ marginTop: 20 }}>
      <TextField
        label={t_i18n('Title')}
        required={context === 'fintelTemplate'}
        fullWidth={true}
        value={parameters.title}
        disabled={dataSelection[0]?.instance_id === SELF_ID}
        onChange={(event) => handleChangeParameter('title', event.target.value)}
      />

      {(context === 'fintelTemplate' && type !== 'attribute') && (
        <div style={{ marginTop: 20 }}>
          <TextField
            label={t_i18n('Variable name')}
            required
            fullWidth={true}
            value={config.fintelVariableName}
            onChange={(event) => setConfigVariableName(event.target.value)}
            error={isWidgetVarNameAlreadyUsed || !isVariableNameValid}
            helperText={varNameError}
            slotProps={{
              input: {
                startAdornment: <InputAdornment position="start">$</InputAdornment>,
              },
            }}
          />
        </div>
      )}

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
            const currentInstanceId = dataSelection[i].instance_id;
            const isNumberError = (dataSelection[i].number ?? 10) > 100;
            return (
              <div key={i}>
                {type === 'attribute' && (
                  <div style={{ marginTop: 20 }}>
                    <FormControl fullWidth={true}>
                      {(currentInstanceId && currentInstanceId !== SELF_ID) ? (
                        <QueryRenderer
                          query={widgetAttributesInputInstanceQuery}
                          variables={{ id: currentInstanceId }}
                          render={({ props: instanceProps }: { props: WidgetAttributesInputContainerInstanceQuery$data }) => {
                            const selectedInstance = instanceProps?.stixCoreObject;
                            return (
                              <EntitySelectWithTypes
                                key="id"
                                label={t_i18n('Instance')}
                                value={selectedInstance ? {
                                  value: selectedInstance.id,
                                  label: selectedInstance.representative.main,
                                  type: selectedInstance.entity_type,
                                } : null}
                                entitiesToExclude={alreadyUsedInstances}
                                handleChange={(value) => handleChangeDataValidationParameter(
                                  i,
                                  'instance_id',
                                  value.value,
                                )}
                              />
                            );
                          }}
                        />
                      ) : (
                        <EntitySelectWithTypes
                          key="id"
                          label={t_i18n('Instance')}
                          disabled={currentInstanceId === SELF_ID}
                          entitiesToExclude={alreadyUsedInstances}
                          value={currentInstanceId === SELF_ID ? {
                            value: SELF_ID,
                            type: 'undefined',
                            label: SELF_ID_VALUE,
                          } : null}
                          handleChange={(value) => handleChangeDataValidationParameter(
                            i,
                            'instance_id',
                            value.value,
                          )}
                        />
                      )}
                    </FormControl>
                  </div>
                )}

                {(getCurrentCategory(type) === 'distribution'
                  || getCurrentCategory(type) === 'list') && (
                  <TextField
                    label={t_i18n('Number of results')}
                    fullWidth={true}
                    type="number"
                    error={isNumberError}
                    helperText={t_i18n('The number of results should be lower than 100')}
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
                        {sortByValues.map((value) => (
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

                {dataSelection[i].perspective !== 'audits' && !['text', 'attribute'].includes(type) && (
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

                {type === 'attribute' && (
                  <WidgetAttributesInputContainer
                    value={dataSelection[i]?.columns ?? []}
                    onChange={(value) => handleChangeDataValidationColumns(i, value)}
                    instanceId={dataSelection[i].instance_id ?? undefined}
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
                          {[
                            { value: 'internal_id', label: 'Entity' },
                            { value: 'entity_type', label: 'Entity type' },
                            { value: 'relationship_type', label: 'Relationship type' },
                            { value: 'created-by.internal_id', label: 'Author' },
                            { value: 'object-marking.internal_id', label: 'Marking definition' },
                            { value: 'kill-chain-phase.internal_id', label: 'Kill chain phase' },
                            { value: 'creator_id', label: 'Creator' },
                            { value: 'x_opencti_workflow_id', label: 'Status' },
                          ].map((n) => (
                            <MenuItem key={n.value} value={n.value}>
                              {t_i18n(n.label)}
                            </MenuItem>
                          ))}
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
        {getCurrentCategory(type) === 'list' && context !== 'fintelTemplate'
          && dataSelection.map(({ perspective, columns, filters }, index) => {
            if (perspective === 'relationships' || perspective === 'entities') {
              const getEntityTypeFromFilters = (filterGroup?: FilterGroup | null): string | undefined => {
                if (!filterGroup) return undefined;

                const entityTypeFilters = getEntityTypeTwoFirstLevelsFilterValues(filterGroup);
                const hasSingleEntityType = entityTypeFilters.length === 1;
                const otherFiltersLength = filterGroup?.filters?.filter((filter) => filter.key !== 'entity_type')?.length;

                if (filterGroup.mode === 'and' && hasSingleEntityType && otherFiltersLength >= 0) {
                  return entityTypeFilters[0];
                }

                if (filterGroup.mode === 'or' && hasSingleEntityType && otherFiltersLength === 0) {
                  return entityTypeFilters[0];
                }

                return undefined;
              };

              const entityType = getEntityTypeFromFilters(filters);

              const defaultWidgetColumnsByType = getDefaultWidgetColumns(perspective, context);
              return (
                <WidgetColumnsCustomizationInput
                  key={index}
                  availableColumns={getWidgetColumns(perspective, entityType || undefined)}
                  defaultColumns={defaultWidgetColumnsByType}
                  value={[...(columns ?? defaultWidgetColumnsByType)]}
                  onChange={(newColumns) => setColumns(index, newColumns)}
                />
              );
            }
            return null;
          })}
      </div>
    </div>
  );
};

export default WidgetCreationParameters;
