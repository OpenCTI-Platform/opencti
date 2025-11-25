import React, { useState } from 'react';
import makeStyles from '@mui/styles/makeStyles';
import { Field, Form, Formik } from 'formik';
import Button from '@mui/material/Button';
import * as Yup from 'yup';
import PlaybookFlowSelectComponent from './playbookFlow/PlaybookFlowSelectComponent';
import Drawer from '../../common/drawer/Drawer';
import TextField from '../../../../components/TextField';
import { useFormatter } from '../../../../components/i18n';
import { deserializeFilterGroupForFrontend, emptyFilterGroup, serializeFilterGroupForBackend } from '../../../../utils/filters/filtersUtils';
import { isEmptyField, isNotEmptyField } from '../../../../utils/utils';
import useFiltersState from '../../../../utils/filters/useFiltersState';
import { parse } from '../../../../utils/Time';
import PlaybookFlowFieldInPirFilters from './playbookFlow/playbookFlowFields/PlaybookFlowFieldInPirFilters';
import PlaybookFlowFieldTargets from './playbookFlow/playbookFlowFields/PlaybookFlowFieldTargets';
import PlaybookFlowFieldCaseTemplates from './playbookFlow/playbookFlowFields/PlaybookFlowFieldCaseTemplates';
import PlaybookFlowFieldFilters from './playbookFlow/playbookFlowFields/PlaybookFlowFieldFilters';
import PlaybookFlowFieldAccessRestrictions from './playbookFlow/playbookFlowFields/PlaybookFlowFieldAccessRestrictions';
import PlaybookFlowFieldAuthorizedMembers from './playbookFlow/playbookFlowFields/PlaybookFlowFieldAuthorizedMembers';
import PlaybookFlowFieldOrganizations from './playbookFlow/playbookFlowFields/PlaybookFlowFieldOrganizations';
import PlaybookFlowFieldArray from './playbookFlow/playbookFlowFields/PlaybookFlowFieldArray';
import PlaybookFlowFieldPeriod from './playbookFlow/playbookFlowFields/PlaybookFlowFieldPeriod';
import PlaybookFlowFieldTriggerTime from './playbookFlow/playbookFlowFields/PlaybookFlowFieldTriggerTime';
import PlaybookFlowFieldNumber from './playbookFlow/playbookFlowFields/PlaybookFlowFieldNumber';
import PlaybookFlowFieldBoolean from './playbookFlow/playbookFlowFields/PlaybookFlowFieldBoolean';
import PlaybookFlowFieldString from './playbookFlow/playbookFlowFields/PlaybookFlowFieldString';
import PlaybookFlowFieldActions from './playbookFlow/playbookFlowFields/playbookFlowFieldsActions/PlaybookFlowFieldActions';

// Deprecated - https://mui.com/system/styles/basics/
// Do not use it for new code.
const useStyles = makeStyles((theme) => ({
  buttons: {
    marginTop: 20,
    textAlign: 'right',
  },
  button: {
    marginLeft: theme.spacing(2),
  },
  config: {
    padding: '0px 0px 20px 0px',
  },
}));

const addComponentValidation = (t) => Yup.object().shape({
  name: Yup.string().trim().required(t('This field is required')),
});

const PlaybookAddComponentsContent = ({
  action,
  selectedNode,
  playbookComponents,
  onConfigAdd,
  onConfigReplace,
  handleClose,
}) => {
  const classes = useStyles();
  const { t_i18n } = useFormatter();
  const currentConfig = action === 'config' ? selectedNode?.data?.configuration : null;
  const initialFilters = currentConfig?.filters ? deserializeFilterGroupForFrontend(currentConfig?.filters) : emptyFilterGroup;
  const filtersState = useFiltersState(initialFilters);
  const [componentId, setComponentId] = useState(
    action === 'config' ? selectedNode?.data?.component?.id ?? null : null,
  );

  const onSubmit = (values, { resetForm }) => {
    const selectedComponent = playbookComponents
      .filter((n) => n.id === componentId)
      .at(0);
    const configurationSchema = JSON.parse(
      selectedComponent.configuration_schema,
    );
    const { name, ...config } = values;
    let finalConfig = config;
    if (configurationSchema?.properties?.filters) {
      const jsonFilters = serializeFilterGroupForBackend(filtersState[0]);
      finalConfig = { ...finalConfig, filters: jsonFilters };
    }
    if (configurationSchema?.properties?.triggerTime) {
      // Important to translate to UTC before formatting
      let triggerTime = `${parse(values.time).utc().format('HH:mm:00.000')}Z`;
      if (values.period !== 'minute' && values.period !== 'hour' && values.period !== 'day') {
        const day = values.day && values.day.length > 0 ? values.day : '1';
        triggerTime = `${day}-${triggerTime}`;
      }
      finalConfig = { ...finalConfig, triggerTime };
    }
    resetForm();
    if (
      selectedNode?.data?.component?.id
            && (action === 'config' || action === 'replace')
    ) {
      onConfigReplace(selectedComponent, name, finalConfig);
    } else {
      onConfigAdd(selectedComponent, name, finalConfig);
    }
  };

  const renderConfig = () => {
    const selectedComponent = playbookComponents
      .filter((n) => n.id === componentId)
      .at(0);
    const configurationSchema = JSON.parse(
      selectedComponent.configuration_schema ?? '{}',
    );
    const defaultConfig = {};
    Object.entries(configurationSchema?.properties ?? {}).forEach(([k, v]) => {
      defaultConfig[k] = v.default;
    });
    const initialValues = currentConfig
      ? {
        name: selectedNode?.data?.component?.id === selectedComponent.id ? selectedNode?.data?.name : selectedComponent.name,
        ...currentConfig,
      }
      : {
        name: selectedComponent.name,
        ...defaultConfig,
      };

    return (
      <div className={classes.config}>
        <Formik
          initialValues={initialValues}
          validationSchema={addComponentValidation(t_i18n)}
          onSubmit={onSubmit}
          onReset={handleClose}
        >
          {({
            submitForm,
            handleReset,
            isSubmitting,
            values,
          }) => {
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
                  fullWidth={true}
                />
                {Object.entries(configurationSchema?.properties ?? {}).map(
                  ([k, v]) => {
                    if (k === 'access_restrictions') {
                      return <PlaybookFlowFieldAccessRestrictions key={k} />;
                    }
                    if (k === 'authorized_members') {
                      return <PlaybookFlowFieldAuthorizedMembers key={k} />;
                    }
                    if (k === 'organizations') {
                      return <PlaybookFlowFieldOrganizations key={k} />;
                    }
                    if (k === 'inPirFilters') {
                      return <PlaybookFlowFieldInPirFilters key={k} />;
                    }
                    if (k === 'targets') {
                      return <PlaybookFlowFieldTargets key={k} />;
                    }
                    if (k === 'caseTemplates') {
                      return <PlaybookFlowFieldCaseTemplates key={k} />;
                    }
                    if (k === 'filters') {
                      return (
                        <PlaybookFlowFieldFilters
                          key={k}
                          componentId={componentId}
                          filtersState={filtersState}
                        />
                      );
                    }
                    if (k === 'period') {
                      return <PlaybookFlowFieldPeriod key={k} />;
                    }
                    if (k === 'triggerTime') {
                      return <PlaybookFlowFieldTriggerTime key={k} />;
                    }
                    if (k === 'actions') {
                      return (
                        <PlaybookFlowFieldActions
                          key={k}
                          operations={v.items?.properties?.op?.enum}
                        />
                      );
                    }
                    if (v.type === 'number') {
                      return (
                        <PlaybookFlowFieldNumber
                          key={k}
                          name={k}
                          label={t_i18n(v.$ref ?? k)}
                        />
                      );
                    }
                    if (v.type === 'boolean') {
                      return (
                        <PlaybookFlowFieldBoolean
                          key={k}
                          name={k}
                          label={t_i18n(v.$ref ?? k)}
                        />
                      );
                    }
                    if (v.type === 'string' && v.oneOf) {
                      return (
                        <PlaybookFlowFieldArray
                          key={k}
                          name={k}
                          label={t_i18n(v.$ref ?? k)}
                          options={v.oneOf}
                        />
                      );
                    }
                    if (v.type === 'array') {
                      return (
                        <PlaybookFlowFieldArray
                          key={k}
                          name={k}
                          label={t_i18n(v.$ref ?? k)}
                          options={v.items.oneOf}
                          multiple
                        />
                      );
                    }
                    return (
                      <PlaybookFlowFieldString
                        key={k}
                        name={k}
                        label={t_i18n(v.$ref ?? k)}
                      />
                    );
                  },
                )}
                <div className="clearfix" />
                <div className={classes.buttons}>
                  <Button
                    variant="contained"
                    onClick={handleReset}
                    disabled={isSubmitting}
                    classes={{ root: classes.button }}
                  >
                    {t_i18n('Cancel')}
                  </Button>
                  <Button
                    variant="contained"
                    color="secondary"
                    onClick={submitForm}
                    disabled={
                    (values.actions?.length > 0 && !actionsAreValid)
                    || isSubmitting
                  }
                    classes={{ root: classes.button }}
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

  return (
    <>
      {isEmptyField(componentId) && (
        <PlaybookFlowSelectComponent
          components={playbookComponents}
          onSelect={setComponentId}
          selectedNode={selectedNode}
        />
      )}
      {isNotEmptyField(componentId) && renderConfig()}
    </>
  );
};

const PlaybookAddComponents = ({
  action,
  setSelectedNode,
  setSelectedEdge,
  selectedNode,
  selectedEdge,
  playbookComponents,
  onConfigAdd,
  onConfigReplace,
}) => {
  const { t_i18n } = useFormatter();
  const handleClose = () => {
    setSelectedNode(null);
    setSelectedEdge(null);
  };
  const open = !!(
    (action === 'config' || action === 'add' || action === 'replace')
        && (selectedNode !== null || selectedEdge || null)
  );
  return (
    <Drawer
      open={open}
      title={t_i18n('Add components')}
      onClose={handleClose}
    >
      {({ onClose }) => (
        <>
          {(selectedNode || selectedEdge) && (
          <PlaybookAddComponentsContent
            playbookComponents={playbookComponents}
            action={action}
            selectedNode={selectedNode}
            onConfigAdd={onConfigAdd}
            onConfigReplace={onConfigReplace}
            handleClose={onClose}
          />
          )}
        </>
      )}
    </Drawer>
  );
};

export default PlaybookAddComponents;
