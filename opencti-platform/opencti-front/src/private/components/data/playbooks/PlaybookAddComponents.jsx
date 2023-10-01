import React, { useState } from 'react';
import Drawer from '@mui/material/Drawer';
import IconButton from '@mui/material/IconButton';
import Typography from '@mui/material/Typography';
import { Close } from '@mui/icons-material';
import makeStyles from '@mui/styles/makeStyles';
import List from '@mui/material/List';
import ListItem from '@mui/material/ListItem';
import ListItemText from '@mui/material/ListItemText';
import * as R from 'ramda';
import { Field, Form, Formik } from 'formik';
import Button from '@mui/material/Button';
import * as Yup from 'yup';
import ListItemIcon from '@mui/material/ListItemIcon';
import Filters from '../../common/lists/Filters';
import FilterIconButton from '../../../../components/FilterIconButton';
import TextField from '../../../../components/TextField';
import SearchInput from '../../../../components/SearchInput';
import { useFormatter } from '../../../../components/i18n';
import { isUniqFilter } from '../../../../utils/filters/filtersUtils';
import ItemIcon from '../../../../components/ItemIcon';

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
  search: {
    float: 'right',
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
  const currentConfig = selectedNode?.data?.configuration;
  const [filters, setFilters] = useState(
    currentConfig?.filters ? JSON.parse(currentConfig?.filters) : {},
  );
  const [componentId, setComponentId] = useState(null);
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
    resetForm();
    if (selectedNode?.data?.component?.id && action === 'config') {
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
      selectedComponent.configuration_schema,
    );
    return (
      <div className={classes.config}>
        <Formik
          initialValues={
            currentConfig
              ? {
                name:
                    selectedNode?.data?.component?.id === selectedComponent.id
                      ? selectedNode?.data?.name
                      : selectedComponent.name,
                ...currentConfig,
              }
              : { name: selectedComponent.name }
          }
          validationSchema={addComponentValidation(t)}
          onSubmit={onSubmit}
          onReset={handleClose}
        >
          {({ submitForm, handleReset, isSubmitting }) => (
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
                  if (v.type === 'number') {
                    return (
                      <Field
                        component={TextField}
                        variant="standard"
                        type="number"
                        name={k}
                        label={t(k)}
                        fullWidth={true}
                      />
                    );
                  }
                  return (
                    <Field
                      component={TextField}
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
                  disabled={isSubmitting}
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
      {componentId === null && renderLines()}
      {componentId !== null && renderConfig()}
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
  const open = (action === 'config' || action === 'add')
    && (selectedNode !== null || selectedEdge || null);
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
        <div className={classes.search}>
          <SearchInput
            variant="inDrawer"
            placeholder={`${t('Search')}...`}
            onChange={setSearchTerm}
          />
        </div>
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
