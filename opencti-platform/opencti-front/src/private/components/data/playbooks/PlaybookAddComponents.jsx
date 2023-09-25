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
import Filters from '../../common/lists/Filters';
import FilterIconButton from '../../../../components/FilterIconButton';
import TextField from '../../../../components/TextField';
import { isEmptyField } from '../../../../utils/utils';
import SearchInput from '../../../../components/SearchInput';
import { useFormatter } from '../../../../components/i18n';
import { isUniqFilter } from '../../../../utils/filters/filtersUtils';

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

const PlaybookAddComponents = ({
  open,
  handleClose,
  selectedNode,
  playbookComponents,
  onConfig,
}) => {
  const classes = useStyles();
  const { t } = useFormatter();
  const [searchTerm, setSearchTerm] = useState('');
  const [filters, setFilters] = useState({});
  const [componentId, setComponentId] = useState(
    selectedNode?.data?.component?.id ?? null,
  );
  const onReset = () => {
    handleClose();
  };
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
  const onSelect = (component) => {
    if (!isEmptyField(JSON.parse(component.configuration_schema))) {
      setComponentId(component.id);
    } else {
      onConfig(component);
    }
  };
  const onSubmit = (values, { resetForm }) => {
    const selectedComponent = playbookComponents
      .filter((n) => n.id === componentId)
      .at(0);
    const configurationSchema = JSON.parse(
      selectedComponent.configuration_schema,
    );
    let config = values;
    if (configurationSchema.properties.filters) {
      const jsonFilters = JSON.stringify(filters);
      config = { ...config, filters: jsonFilters };
    }
    resetForm();
    onConfig(selectedComponent, config);
  };
  const renderLines = () => {
    const filterByKeyword = (n) => searchTerm === ''
      || n.name.toLowerCase().indexOf(searchTerm.toLowerCase()) !== -1
      || n.description.toLowerCase().indexOf(searchTerm.toLowerCase()) !== -1;
    const components = R.pipe(
      R.filter(
        (n) => n.is_entry_point === (selectedNode?.data?.isEntryPoint ?? false),
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
                onClick={() => onSelect(component)}
              >
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
          initialValues={{ name: selectedComponent.name }}
          onSubmit={onSubmit}
          onReset={onReset}
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
              {Object.entries(configurationSchema.properties).map(([k, v]) => {
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
              })}
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
                  {t('Create')}
                </Button>
              </div>
            </Form>
          )}
        </Formik>
      </div>
    );
  };
  return (
    <Drawer
      open={open}
      anchor="right"
      elevation={1}
      sx={{ zIndex: 1202 }}
      classes={{ paper: classes.drawerPaper }}
      onClose={() => handleClose()}
    >
      <div className={classes.header}>
        <IconButton
          aria-label="Close"
          className={classes.closeButton}
          onClick={() => handleClose()}
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
      {componentId === null && renderLines()}
      {componentId !== null && renderConfig()}
    </Drawer>
  );
};

export default PlaybookAddComponents;
