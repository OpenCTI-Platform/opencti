import React, { useState } from 'react';
import Drawer from '@mui/material/Drawer';
import IconButton from '@mui/material/IconButton';
import Typography from '@mui/material/Typography';
import { AddOutlined, CancelOutlined, Close } from '@mui/icons-material';
import makeStyles from '@mui/styles/makeStyles';
import List from '@mui/material/List';
import ListItem from '@mui/material/ListItem';
import ListItemText from '@mui/material/ListItemText';
import * as R from 'ramda';
import { Field, Form, Formik } from 'formik';
import Button from '@mui/material/Button';
import * as Yup from 'yup';
import ListItemIcon from '@mui/material/ListItemIcon';
import Grid from '@mui/material/Grid';
import FormControl from '@mui/material/FormControl';
import InputLabel from '@mui/material/InputLabel';
import Select from '@mui/material/Select';
import MenuItem from '@mui/material/MenuItem';
import Tooltip from '@mui/material/Tooltip';
import CreatedByField from '../../common/form/CreatedByField';
import Filters from '../../common/lists/Filters';
import FilterIconButton from '../../../../components/FilterIconButton';
import TextField from '../../../../components/TextField';
import { useFormatter } from '../../../../components/i18n';
import { isUniqFilter } from '../../../../utils/filters/filtersUtils';
import ItemIcon from '../../../../components/ItemIcon';
import { isEmptyField, isNotEmptyField } from '../../../../utils/utils';
import SwitchField from '../../../../components/SwitchField';
import ObjectMarkingField from '../../common/form/ObjectMarkingField';
import ObjectLabelField from '../../common/form/ObjectLabelField';
import StatusField from '../../common/form/StatusField';
import { numberAttributes } from '../../../../utils/hooks/useAttributes';
import AutocompleteField from '../../../../components/AutocompleteField';

const useStyles = makeStyles((theme) => ({
  drawerPaper: {
    minHeight: '100vh',
    width: '50%',
    padding: 0,
  },
  header: {
    backgroundColor: theme.palette.background.nav,
    padding: '20px 20px 20px 60px',
  },
  closeButton: {
    position: 'absolute',
    top: 12,
    left: 5,
    color: 'inherit',
  },
  title: {
    float: 'left',
  },
  lines: {
    padding: 0,
    height: '100%',
    width: '100%',
  },
  buttons: {
    marginTop: 20,
    textAlign: 'right',
  },
  button: {
    marginLeft: theme.spacing(2),
  },
  config: {
    padding: '10px 20px 20px 20px',
  },
  container: {
    marginTop: 40,
  },
  step: {
    position: 'relative',
    width: '100%',
    margin: '0 0 20px 0',
    padding: 15,
    verticalAlign: 'middle',
    border: `1px solid ${theme.palette.background.accent}`,
    borderRadius: 5,
    display: 'flex',
  },
  formControl: {
    width: '100%',
  },
  buttonAdd: {
    width: '100%',
    height: 20,
  },
  stepCloseButton: {
    position: 'absolute',
    top: -20,
    right: -20,
  },
}));

const addComponentValidation = (t) => Yup.object().shape({
  name: Yup.string().required(t('This field is required')),
});

const PlaybookAddComponentsContent = ({
  searchTerm,
  action,
  selectedNode,
  playbookComponents,
  onConfigAdd,
  onConfigReplace,
  handleClose,
}) => {
  const classes = useStyles();
  const { t } = useFormatter();
  const currentConfig = action === 'config' ? selectedNode?.data?.configuration : null;
  const [filters, setFilters] = useState(
    currentConfig?.filters ? JSON.parse(currentConfig?.filters) : {},
  );
  const [actionsInputs, setActionsInputs] = useState(
    currentConfig?.actions ? currentConfig.actions : [],
  );
  const [componentId, setComponentId] = useState(
    action === 'config' ? selectedNode?.data?.component?.id ?? null : null,
  );
  const handleAddFilter = (key, id, value) => {
    if (filters[key] && filters[key].length > 0) {
      setFilters({
        ...filters,
        [key]: isUniqFilter(key)
          ? [{ id, value }]
          : R.uniqBy(R.prop('id'), [{ id, value }, ...filters[key]]),
      });
    } else {
      setFilters({ ...filters, [key]: [{ id, value }] });
    }
  };
  const handleRemoveFilter = (key) => {
    setFilters(R.dissoc(key, filters));
  };
  const handleAddStep = () => {
    setActionsInputs(R.append({}, actionsInputs));
  };
  const handleRemoveStep = (i) => {
    setActionsInputs(R.remove(i, 1, actionsInputs));
  };
  const handleChangeActionInput = (i, key, value) => {
    setActionsInputs(
      actionsInputs.map((v, k) => {
        if (k === i) {
          return { ...v, [key]: value };
        }
        return v;
      }),
    );
  };
  const areStepsValid = () => {
    for (const n of actionsInputs) {
      if (!n || !n.op || !n.attribute || !n.value || n.value.length === 0) {
        return false;
      }
    }
    return true;
  };
  const renderFieldOptions = (i, values, setValues) => {
    const disabled = isEmptyField(actionsInputs[i]?.op);
    let options = [];
    if (actionsInputs[i]?.op === 'add') {
      options = [
        {
          label: t('Marking definitions'),
          value: 'objectMarking',
          isMultiple: true,
        },
        { label: t('Labels'), value: 'objectLabel', isMultiple: true },
      ];
    } else if (actionsInputs[i]?.op === 'replace') {
      options = [
        {
          label: t('Marking definitions'),
          value: 'objectMarking',
          isMultiple: true,
        },
        { label: t('Labels'), value: 'objectLabel', isMultiple: true },
        { label: t('Author'), value: 'createdBy', isMultiple: false },
        { label: t('Confidence'), value: 'confidence', isMultiple: false },
        { label: t('Score'), value: 'x_opencti_score', isMultiple: false },
        {
          label: t('Detection'),
          value: 'x_opencti_detection',
          isMultiple: false,
        },
        {
          label: t('Status'),
          value: 'x_opencti_workflow_id',
          isMultiple: false,
        },
      ];
    } else if (actionsInputs[i]?.op === 'remove') {
      options = [
        {
          label: t('Marking definitions'),
          value: 'objectMarking',
          isMultiple: true,
        },
        { label: t('Labels'), value: 'objectLabel', isMultiple: true },
      ];
    }
    return (
      <Select
        variant="standard"
        disabled={disabled}
        value={actionsInputs[i]?.attribute}
        onChange={(event) => {
          handleChangeActionInput(i, 'attribute', event.target.value);
          setValues(R.omit([`actions-${i}-value`], values));
        }}
      >
        {options.length > 0 ? (
          R.map(
            (n) => (
              <MenuItem key={n.value} value={n.value}>
                {n.label}
              </MenuItem>
            ),
            options,
          )
        ) : (
          <MenuItem value="none">{t('None')}</MenuItem>
        )}
      </Select>
    );
  };
  const renderValuesOptions = (i) => {
    const disabled = isEmptyField(actionsInputs[i]?.attribute);
    switch (actionsInputs[i]?.attribute) {
      case 'objectMarking':
        return (
          <ObjectMarkingField
            name={`actions-${i}-value`}
            disabled={disabled}
            onChange={(_, value) => handleChangeActionInput(
              i,
              'value',
              value.map((n) => ({
                label: n.label,
                value: n.value,
                patch_value: n.value,
              })),
            )
            }
          />
        );
      case 'objectLabel':
        return (
          <ObjectLabelField
            name={`actions-${i}-value`}
            disabled={disabled}
            onChange={(_, value) => handleChangeActionInput(
              i,
              'value',
              value.map((n) => ({
                label: n.label,
                value: n.value,
                patch_value: n.label,
              })),
            )
            }
          />
        );
      case 'createdBy':
        return (
          <CreatedByField
            name={`actions-${i}-value`}
            disabled={disabled}
            onChange={(_, value) => handleChangeActionInput(i, 'value', [
              {
                label: value.label,
                value: value.value,
                patch_value: value.value,
              },
            ])
            }
          />
        );
      case 'x_opencti_workflow_id':
        return (
          <StatusField
            name={`actions-${i}-value`}
            disabled={disabled}
            onChange={(_, value) => handleChangeActionInput(i, 'value', [
              {
                label: value.label,
                value: value.value,
                patch_value: value.value,
              },
            ])
            }
          />
        );
      default:
        return (
          <Field
            component={TextField}
            disabled={disabled}
            type={
              numberAttributes.includes(actionsInputs[i]?.attribute)
                ? 'number'
                : 'text'
            }
            variant="standard"
            name={`actions-${i}-value`}
            label={t('Value')}
            fullWidth={true}
            onChange={(_, value) => handleChangeActionInput(i, 'value', [
              { label: value, value, patch_value: value },
            ])
            }
          />
        );
    }
  };
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
      const jsonFilters = JSON.stringify(filters);
      finalConfig = { ...config, filters: jsonFilters };
    }
    if (configurationSchema?.properties?.actions) {
      finalConfig = { ...config, actions: actionsInputs };
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
  const renderLines = () => {
    const filterByKeyword = (n) => searchTerm === ''
      || n.name.toLowerCase().indexOf(searchTerm.toLowerCase()) !== -1
      || n.description.toLowerCase().indexOf(searchTerm.toLowerCase()) !== -1;
    const components = R.pipe(
      R.filter(
        (n) => n.is_entry_point
          === (selectedNode?.data?.component?.is_entry_point ?? false),
      ),
      R.filter(filterByKeyword),
    )(playbookComponents);
    return (
      <div className={classes.lines}>
        <List>
          {components.map((component) => {
            return (
              <ListItem
                key={component.id}
                divider={true}
                button={true}
                clases={{ root: classes.item }}
                onClick={() => setComponentId(component.id)}
              >
                <ListItemIcon>
                  <ItemIcon type={component.icon} />
                </ListItemIcon>
                <ListItemText
                  primary={component.name}
                  secondary={component.description}
                />
              </ListItem>
            );
          })}
        </List>
      </div>
    );
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
        name:
            selectedNode?.data?.component?.id === selectedComponent.id
              ? selectedNode?.data?.name
              : selectedComponent.name,
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
          validationSchema={addComponentValidation(t)}
          onSubmit={onSubmit}
          onReset={handleClose}
        >
          {({
            submitForm,
            handleReset,
            isSubmitting,
            setValues,
            values,
            setFieldValue,
          }) => (
            <Form style={{ margin: '20px 0 20px 0' }}>
              <Field
                component={TextField}
                variant="standard"
                name="name"
                label={t('Name')}
                fullWidth={true}
              />
              {Object.entries(configurationSchema?.properties ?? {}).map(
                ([k, v]) => {
                  if (k === 'filters') {
                    return (
                      <div key={k}>
                        <div style={{ marginTop: 35 }}>
                          <Filters
                            variant="text"
                            availableFilterKeys={[
                              'entity_type',
                              'x_opencti_workflow_id',
                              'assigneeTo',
                              'objectContains',
                              'markedBy',
                              'labelledBy',
                              'creator',
                              'createdBy',
                              'priority',
                              'severity',
                              'x_opencti_score',
                              'x_opencti_detection',
                              'revoked',
                              'confidence',
                              'indicator_types',
                              'pattern_type',
                              'x_opencti_main_observable_type',
                              'fromId',
                              'toId',
                              'fromTypes',
                              'toTypes',
                            ]}
                            handleAddFilter={handleAddFilter}
                            noDirectFilters={true}
                          />
                        </div>
                        <div className="clearfix" />
                        <FilterIconButton
                          filters={filters}
                          handleRemoveFilter={handleRemoveFilter}
                          classNameNumber={2}
                          styleNumber={2}
                          redirection
                        />
                        <div className="clearfix" />
                      </div>
                    );
                  }
                  if (k === 'actions') {
                    return (
                      <div
                        key={k}
                        className={classes.container}
                        style={{ marginTop: 20 }}
                      >
                        {Array(actionsInputs.length)
                          .fill(0)
                          .map((_, i) => (
                            <div key={i} className={classes.step}>
                              <IconButton
                                disabled={actionsInputs.length === 1}
                                aria-label="Delete"
                                className={classes.stepCloseButton}
                                onClick={() => {
                                  handleRemoveStep(i);
                                  setValues(
                                    R.omit([`actions-${i}-value`], values),
                                  );
                                }}
                                size="small"
                              >
                                <CancelOutlined fontSize="small" />
                              </IconButton>
                              <Grid container={true} spacing={3}>
                                <Grid item={true} xs={3}>
                                  <FormControl className={classes.formControl}>
                                    <InputLabel>{t('Action type')}</InputLabel>
                                    <Select
                                      variant="standard"
                                      value={actionsInputs[i]?.op}
                                      onChange={(event) => handleChangeActionInput(
                                        i,
                                        'op',
                                        event.target.value,
                                      )
                                      }
                                    >
                                      <MenuItem value="add">
                                        {t('Add')}
                                      </MenuItem>
                                      <MenuItem value="replace">
                                        {t('Replace')}
                                      </MenuItem>
                                      <MenuItem value="remove">
                                        {t('Remove')}
                                      </MenuItem>
                                    </Select>
                                  </FormControl>
                                </Grid>
                                <Grid item={true} xs={3}>
                                  <FormControl className={classes.formControl}>
                                    <InputLabel>{t('Field')}</InputLabel>
                                    {renderFieldOptions(i, values, setValues)}
                                  </FormControl>
                                </Grid>
                                <Grid item={true} xs={6}>
                                  {renderValuesOptions(i)}
                                </Grid>
                              </Grid>
                            </div>
                          ))}
                        <div className={classes.add}>
                          <Button
                            disabled={!areStepsValid()}
                            variant="contained"
                            color="secondary"
                            size="small"
                            onClick={handleAddStep}
                            classes={{ root: classes.buttonAdd }}
                          >
                            <AddOutlined fontSize="small" />
                          </Button>
                        </div>
                      </div>
                    );
                  }
                  if (v.type === 'number') {
                    return (
                      <Field
                        key={k}
                        component={TextField}
                        variant="standard"
                        type="number"
                        name={k}
                        label={t(k)}
                        fullWidth={true}
                        style={{ marginTop: 20, width: '100%' }}
                      />
                    );
                  }
                  if (v.type === 'boolean') {
                    return (
                      <Field
                        key={k}
                        component={SwitchField}
                        type="checkbox"
                        name={k}
                        label={t(k)}
                        containerstyle={{ marginTop: 20 }}
                      />
                    );
                  }
                  if (v.type === 'string' && isNotEmptyField(v.oneOf)) {
                    return (
                      <Field
                        key={k}
                        component={AutocompleteField}
                        name={k}
                        fullWidth={true}
                        multiple={false}
                        style={{ marginTop: 20, width: '100%' }}
                        renderOption={(optionProps, value) => (
                          <Tooltip
                            {...optionProps}
                            key={value.const}
                            title={value.title}
                            placement="bottom-start"
                          >
                            <MenuItem value={value.const}>
                              {value.title}
                            </MenuItem>
                          </Tooltip>
                        )}
                        isOptionEqualToValue={(option, value) => option.const === value
                        }
                        onInternalChange={(name, value) => setFieldValue(name, value.const ? value.const : value)
                        }
                        options={v.oneOf}
                        textfieldprops={{
                          variant: 'standard',
                          label: t(k),
                        }}
                        getOptionLabel={(option) => (option.title
                          ? option.title
                          : v.oneOf?.filter((n) => n.const === option)?.at(0)
                            ?.title ?? option)
                        }
                      />
                    );
                  }
                  if (v.type === 'array') {
                    return (
                      <Field
                        key={k}
                        component={AutocompleteField}
                        name={k}
                        fullWidth={true}
                        multiple={true}
                        style={{ marginTop: 20, width: '100%' }}
                        renderOption={(optionProps, value) => (
                          <Tooltip
                            {...optionProps}
                            key={value.const}
                            title={value.title}
                            placement="bottom-start"
                          >
                            <MenuItem value={value.const}>
                              {value.title}
                            </MenuItem>
                          </Tooltip>
                        )}
                        isOptionEqualToValue={(option, value) => option.const === value
                        }
                        onInternalChange={(name, value) => setFieldValue(
                          name,
                          value.map((n) => (n.const ? n.const : n)),
                        )
                        }
                        noFieldUpdate={true}
                        options={v.items.oneOf}
                        textfieldprops={{
                          variant: 'standard',
                          label: t(k),
                        }}
                        getOptionLabel={(option) => (option.title
                          ? option.title
                          : v.items.oneOf
                            ?.filter((n) => n.const === option)
                            ?.at(0)?.title ?? option)
                        }
                      />
                    );
                  }
                  return (
                    <Field
                      key={k}
                      component={TextField}
                      style={{ marginTop: 20, width: '100%' }}
                      variant="standard"
                      name={k}
                      label={t(k)}
                      fullWidth={true}
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
                  {t('Cancel')}
                </Button>
                <Button
                  variant="contained"
                  color="secondary"
                  onClick={submitForm}
                  disabled={
                    (actionsInputs.length > 0 && !areStepsValid())
                    || isSubmitting
                  }
                  classes={{ root: classes.button }}
                >
                  {selectedNode?.data?.component?.id
                    ? t('Update')
                    : t('Create')}
                </Button>
              </div>
            </Form>
          )}
        </Formik>
      </div>
    );
  };
  return (
    <>
      {isEmptyField(componentId) && renderLines()}
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
  const classes = useStyles();
  const { t } = useFormatter();
  const [searchTerm, setSearchTerm] = useState('');
  const handleClose = () => {
    setSearchTerm('');
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
      anchor="right"
      elevation={1}
      sx={{ zIndex: 1202 }}
      classes={{ paper: classes.drawerPaper }}
      onClose={handleClose}
    >
      <div className={classes.header}>
        <IconButton
          aria-label="Close"
          className={classes.closeButton}
          onClick={handleClose}
          size="large"
          color="primary"
        >
          <Close fontSize="small" color="primary" />
        </IconButton>
        <Typography variant="h6" classes={{ root: classes.title }}>
          {t('Add components')}
        </Typography>
      </div>
      {(selectedNode || selectedEdge) && (
        <PlaybookAddComponentsContent
          searchTerm={searchTerm}
          playbookComponents={playbookComponents}
          action={action}
          selectedNode={selectedNode}
          onConfigAdd={onConfigAdd}
          onConfigReplace={onConfigReplace}
          handleClose={handleClose}
        />
      )}
    </Drawer>
  );
};

export default PlaybookAddComponents;
