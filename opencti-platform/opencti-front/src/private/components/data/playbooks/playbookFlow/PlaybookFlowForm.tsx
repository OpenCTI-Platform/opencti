/*
Copyright (c) 2021-2025 Filigran SAS

This file is part of the OpenCTI Enterprise Edition ("EE") and is
licensed under the OpenCTI Enterprise Edition License (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

https://github.com/OpenCTI-Platform/opencti/blob/master/LICENSE

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
*/

import { Field, Form, Formik, FormikConfig } from 'formik';
import Button from '@common/button/Button';
import { useTheme } from '@mui/styles';
import * as Yup from 'yup';
import { useFormatter } from '../../../../../components/i18n';
import useFiltersState from '../../../../../utils/filters/useFiltersState';
import { parse } from '../../../../../utils/Time';
import { deserializeFilterGroupForFrontend, emptyFilterGroup, serializeFilterGroupForBackend } from '../../../../../utils/filters/filtersUtils';
import PlaybookFlowFieldInPirFilters from './playbookFlowFields/PlaybookFlowFieldInPirFilters';
import PlaybookFlowFieldTargets from './playbookFlowFields/PlaybookFlowFieldTargets';
import PlaybookFlowFieldCaseTemplates from './playbookFlowFields/PlaybookFlowFieldCaseTemplates';
import PlaybookFlowFieldFilters from './playbookFlowFields/PlaybookFlowFieldFilters';
import PlaybookFlowFieldAccessRestrictions from './playbookFlowFields/PlaybookFlowFieldAccessRestrictions';
import PlaybookFlowFieldAuthorizedMembers from './playbookFlowFields/PlaybookFlowFieldAuthorizedMembers';
import PlaybookFlowFieldOrganizations from './playbookFlowFields/PlaybookFlowFieldOrganizations';
import PlaybookFlowFieldArray, { PlaybookFlowFieldArrayProps } from './playbookFlowFields/PlaybookFlowFieldArray';
import PlaybookFlowFieldPeriod from './playbookFlowFields/PlaybookFlowFieldPeriod';
import PlaybookFlowFieldTriggerTime from './playbookFlowFields/PlaybookFlowFieldTriggerTime';
import PlaybookFlowFieldNumber from './playbookFlowFields/PlaybookFlowFieldNumber';
import PlaybookFlowFieldBoolean from './playbookFlowFields/PlaybookFlowFieldBoolean';
import PlaybookFlowFieldString from './playbookFlowFields/PlaybookFlowFieldString';
import PlaybookFlowFieldActions from './playbookFlowFields/playbookFlowFieldsActions/PlaybookFlowFieldActions';
import TextField from '../../../../../components/TextField';
import type { Theme } from '../../../../../components/Theme';
import type { PlaybookComponentConfigSchema, PlaybookComponents, PlaybookConfig, PlaybookNode } from '../types/playbook-types';
import { PlaybookUpdateAction, PlaybookUpdateActionsForm } from './playbookFlowFields/playbookFlowFieldsActions/playbookAction-types';
import PeriodicityField from '../../../../../components/fields/PeriodicityField';
import { fieldSpacingContainerStyle } from '../../../../../utils/field';
import SelectField from '../../../../../components/fields/SelectField';
import MenuItem from '@mui/material/MenuItem';
import OpenVocabField from '@components/common/form/OpenVocabField';

export type PlaybookFlowFormData
  // Component: update knowledge
  = PlaybookUpdateActionsForm
    & {
    // Common for every component
      name: string;
      // Component: CRON
      time?: string;
      period?: string;
      day?: string;
    };

interface PlaybookFlowFormProps {
  action: string | null;
  selectedNode: PlaybookNode | null;
  playbookComponents: PlaybookComponents;
  componentId: string | null;
  onConfigAdd: (component: unknown, name: string, config: unknown) => void;
  onConfigReplace: (component: unknown, name: string, config: unknown) => void;
  handleClose: () => void;
}

const PlaybookFlowForm = ({
  action,
  selectedNode,
  playbookComponents,
  componentId,
  onConfigAdd,
  onConfigReplace,
  handleClose,
}: PlaybookFlowFormProps) => {
  const theme = useTheme<Theme>();
  const { t_i18n } = useFormatter();
  const nodeData = action === 'config' ? selectedNode?.data : undefined;
  const currentConfig = nodeData?.configuration ?? null;

  const filtersState = useFiltersState(currentConfig?.filters
    ? deserializeFilterGroupForFrontend(currentConfig.filters)
    : emptyFilterGroup,
  );

  const selectedComponent = playbookComponents.find((c) => c?.id === componentId);
  const configurationSchema = selectedComponent?.configuration_schema
    ? JSON.parse(selectedComponent.configuration_schema) as PlaybookComponentConfigSchema
    : null;

  // Submit function that formats correctly the data for the backend.
  const onSubmit: FormikConfig<PlaybookFlowFormData>['onSubmit'] = (values, { resetForm }) => {
    const { name, actionsFormValues, ...config } = values;
    let finalConfig: PlaybookConfig = config;

    // Special work in case of filters,
    // (get filters from React state and and them in config).
    if (configurationSchema?.properties?.filters) {
      const jsonFilters = serializeFilterGroupForBackend(filtersState[0]);
      finalConfig = { ...finalConfig, filters: jsonFilters };
    }
    // Special work in case of CRON component,
    // (format trigger time to have correct format).
    if (configurationSchema?.properties?.triggerTime) {
      // Important to translate to UTC before formatting
      let triggerTime = `${parse(values.time).utc().format('HH:mm:00.000')}Z`;
      if (values.period !== 'minute' && values.period !== 'hour' && values.period !== 'day') {
        const day = values.day && values.day.length > 0 ? values.day : '1';
        triggerTime = `${day}-${triggerTime}`;
      }
      finalConfig = { ...finalConfig, triggerTime };
    }
    // Special work in case of update knowledge actions,
    // (transform the array to object keys, needed to keep same format as before refactoring).
    if (actionsFormValues) {
      actionsFormValues.forEach((value, i) => {
        // eslint-disable-next-line @typescript-eslint/ban-ts-comment
        // @ts-ignore
        finalConfig[`actions-${i}-value`] = value;
      });
    }

    resetForm();
    if (nodeData?.component?.id && (action === 'config' || action === 'replace')) {
      onConfigReplace(selectedComponent, name, finalConfig);
    } else {
      onConfigAdd(selectedComponent, name, finalConfig);
    }
  };

  const addComponentValidation = Yup.object().shape({
    name: Yup.string().trim().required(t_i18n('This field is required')),
  });

  // region initial values

  const initialValues: PlaybookFlowFormData = {
    name: '',
  };

  if (!currentConfig) {
    // Get default values from schema.
    initialValues.name = selectedComponent?.name ?? '';
    Object.entries(configurationSchema?.properties ?? {})
      .forEach(([propName, property]) => {
      // eslint-disable-next-line @typescript-eslint/ban-ts-comment
      // @ts-ignore
        initialValues[propName] = property.default;
        if (propName === 'actions') initialValues.actionsFormValues = [];
      });
  } else {
    // Get values from saved config.
    initialValues.name = nodeData?.component?.id === selectedComponent?.id
      ? nodeData?.name ?? ''
      : selectedComponent?.name ?? '';
    const actionsFormValues: PlaybookUpdateAction['value'][] = [];
    Object.entries(currentConfig)
      .sort(([keyA], [keyB]) => keyA.localeCompare(keyB))
      .forEach(([key, value]) => {
        if (/actions-\d-value/.test(key)) actionsFormValues.push(value);
        else {
        // eslint-disable-next-line @typescript-eslint/ban-ts-comment
        // @ts-ignore
          initialValues[key] = value;
        }
        initialValues.actionsFormValues = actionsFormValues;
      });
  }

  // endregion

  return (
    <div style={{ padding: '0px 0px 20px 0px' }}>
      <Formik
        initialValues={initialValues}
        validationSchema={addComponentValidation}
        onSubmit={onSubmit}
        onReset={handleClose}
      >
        {({ submitForm, handleReset, isSubmitting, values }) => {
          const actionsAreValid = (values.actions ?? []).every((a) => {
            if (a.attribute === 'x_opencti_detection') return true;
            return a.op && a.attribute && a.value && a.value.length > 0;
          });

          return (
            <Form>
              <Field
                component={TextField}
                variant="standard"
                name="name"
                value={values.name ? t_i18n(values.name) : ''}
                label={t_i18n('Name')}
                fullWidth
              />
              {Object.entries(configurationSchema?.properties ?? {}).map(
                ([propName, property]) => {
                  if (propName === 'access_restrictions') {
                    return <PlaybookFlowFieldAccessRestrictions key={propName} />;
                  }
                  if (propName === 'authorized_members') {
                    return <PlaybookFlowFieldAuthorizedMembers key={propName} />;
                  }
                  if (propName === 'periodicity' || propName === 'duration') {
                    return (
                      <PeriodicityField
                        key={propName}
                        name={propName}
                        label={t_i18n(property.$ref)}
                        style={fieldSpacingContainerStyle}
                      />
                    );
                  }
                  if (propName === 'type_affinity') {
                    return (
                      <Field
                        key={propName}
                        component={SelectField}
                        variant="standard"
                        name="type_affinity"
                        label={t_i18n('Type affinity')}
                        fullWidth={true}
                        containerstyle={{ width: '100%', marginTop: 20 }}
                      >
                        <MenuItem key="ENDPOINT" value="ENDPOINT">
                          {t_i18n('Endpoint')}
                        </MenuItem>
                        <MenuItem key="CLOUD" value="CLOUD">
                          {t_i18n('Cloud')}
                        </MenuItem>
                        <MenuItem key="WEB" value="WEB">
                          {t_i18n('Web')}
                        </MenuItem>
                        <MenuItem key="TABLE-TOP" value="TABLE-TOP">
                          {t_i18n('Table-top')}
                        </MenuItem>
                      </Field>
                    );
                  }
                  if (propName === 'platforms_affinity') {
                    return (
                      <OpenVocabField
                        key={propName}
                        name={propName}
                        type="platforms_ov"
                        label={t_i18n(property.$ref)}
                        containerStyle={fieldSpacingContainerStyle}
                        multiple={true}
                      />
                    );
                  }
                  if (propName === 'organizations') {
                    return <PlaybookFlowFieldOrganizations key={propName} />;
                  }
                  if (propName === 'inPirFilters') {
                    return <PlaybookFlowFieldInPirFilters key={propName} />;
                  }
                  if (propName === 'targets') {
                    return <PlaybookFlowFieldTargets key={propName} />;
                  }
                  if (propName === 'caseTemplates') {
                    return <PlaybookFlowFieldCaseTemplates key={propName} />;
                  }
                  if (propName === 'filters') {
                    return (
                      <PlaybookFlowFieldFilters
                        key={propName}
                        componentId={componentId}
                        filtersState={filtersState}
                      />
                    );
                  }
                  if (propName === 'period') {
                    return <PlaybookFlowFieldPeriod key={propName} />;
                  }
                  if (propName === 'triggerTime') {
                    return <PlaybookFlowFieldTriggerTime key={propName} />;
                  }
                  if (propName === 'actions') {
                    return (
                      <PlaybookFlowFieldActions
                        key={propName}
                        operations={property.items?.properties?.op?.enum}
                      />
                    );
                  }
                  if (property.type === 'number') {
                    return (
                      <PlaybookFlowFieldNumber
                        key={propName}
                        name={propName}
                        label={t_i18n(property.$ref ?? propName)}
                      />
                    );
                  }
                  if (property.type === 'boolean') {
                    let helperText = '';
                    if (propName === 'create_rel') {
                      helperText = t_i18n('If both entities are of interest for selected PIR, then the target is kept');
                    }
                    return (
                      <PlaybookFlowFieldBoolean
                        key={propName}
                        name={propName}
                        helperText={helperText}
                        label={t_i18n(property.$ref ?? propName)}
                      />
                    );
                  }
                  if (property.type === 'string' && property.oneOf) {
                    return (
                      <PlaybookFlowFieldArray
                        key={propName}
                        name={propName}
                        label={t_i18n(property.$ref ?? propName)}
                        options={property.oneOf as PlaybookFlowFieldArrayProps['options']}
                      />
                    );
                  }
                  if (property.type === 'array') {
                    return (
                      <PlaybookFlowFieldArray
                        key={propName}
                        name={propName}
                        label={t_i18n(property.$ref ?? propName)}
                        options={(property.items?.oneOf ?? []) as PlaybookFlowFieldArrayProps['options']}
                        multiple
                      />
                    );
                  }
                  return (
                    <PlaybookFlowFieldString
                      key={propName}
                      name={propName}
                      label={t_i18n(property.$ref ?? propName)}
                    />
                  );
                },
              )}
              <div style={{ marginTop: 20, textAlign: 'right' }}>
                <Button
                  variant="secondary"
                  onClick={handleReset}
                  disabled={isSubmitting}
                  style={{ marginRight: theme.spacing(2) }}
                >
                  {t_i18n('Cancel')}
                </Button>
                <Button
                  onClick={submitForm}
                  disabled={!actionsAreValid || isSubmitting}
                >
                  {selectedNode?.data?.component?.id
                    ? t_i18n('Update')
                    : t_i18n('Create')}
                </Button>
              </div>
            </Form>
          );
        }}
      </Formik>
    </div>
  );
};

export default PlaybookFlowForm;
