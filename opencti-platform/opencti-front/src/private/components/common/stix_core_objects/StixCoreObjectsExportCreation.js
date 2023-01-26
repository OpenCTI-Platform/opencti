import React, { useState } from 'react';
import * as R from 'ramda';
import Dialog from '@mui/material/Dialog';
import DialogTitle from '@mui/material/DialogTitle';
import DialogContent from '@mui/material/DialogContent';
import DialogActions from '@mui/material/DialogActions';
import Button from '@mui/material/Button';
import { Add } from '@mui/icons-material';
import { graphql, createFragmentContainer } from 'react-relay';
import { Form, Formik, Field } from 'formik';
import MenuItem from '@mui/material/MenuItem';
import IconButton from '@mui/material/IconButton';
import * as Yup from 'yup';
import Tooltip from '@mui/material/Tooltip';
import makeStyles from '@mui/styles/makeStyles';
import { useFormatter } from '../../../../components/i18n';
import {
  commitMutation,
  MESSAGING$,
  QueryRenderer,
} from '../../../../relay/environment';
import { markingDefinitionsLinesSearchQuery } from '../../settings/marking_definitions/MarkingDefinitionsLines';
import SelectField from '../../../../components/SelectField';
import Loader from '../../../../components/Loader';
import { ExportContext } from '../../../../utils/ExportContextProvider';

const useStyles = makeStyles((theme) => ({
  createButton: {
    float: 'left',
  },
  drawerPaper: {
    minHeight: '100vh',
    width: 250,
    padding: '0 0 20px 0',
    position: 'fixed',
    transition: theme.transitions.create('width', {
      easing: theme.transitions.easing.sharp,
      duration: theme.transitions.duration.enteringScreen,
    }),
  },
  listIcon: {
    marginRight: 0,
  },
  item: {
    padding: '0 0 0 10px',
  },
  itemField: {
    padding: '0 15px 0 15px',
  },
  toolbar: theme.mixins.toolbar,
}));

export const StixCoreObjectsExportCreationMutation = graphql`
  mutation StixCoreObjectsExportCreationMutation(
    $type: String!
    $format: String!
    $exportType: String!
    $maxMarkingDefinition: String
    $context: String
    $search: String
    $orderBy: StixCoreObjectsOrdering
    $orderMode: OrderingMode
    $filters: [StixCoreObjectsFiltering]
    $relationship_type: [String]
    $elementId: String
  ) {
    stixCoreObjectsExportAsk(
      type: $type
      format: $format
      exportType: $exportType
      maxMarkingDefinition: $maxMarkingDefinition
      context: $context
      search: $search
      orderBy: $orderBy
      orderMode: $orderMode
      filters: $filters
      relationship_type: $relationship_type
      elementId: $elementId
    ) {
      edges {
        node {
          id
          name
          uploadStatus
          lastModifiedSinceMin
        }
      }
    }
  }
`;

const exportValidation = (t) => Yup.object().shape({
  format: Yup.string().required(t('This field is required')),
});

export const scopesConn = (exportConnectors) => {
  const scopes = R.uniq(
    R.flatten(R.map((c) => c.connector_scope, exportConnectors)),
  );
  const connectors = R.map((s) => {
    const filteredConnectors = R.filter(
      (e) => R.includes(s, e.connector_scope),
      exportConnectors,
    );
    return R.map(
      (x) => ({ data: { name: x.name, active: x.active } }),
      filteredConnectors,
    );
  }, scopes);
  const zipped = R.zip(scopes, connectors);
  return R.fromPairs(zipped);
};

const StixCoreObjectsExportCreationComponent = ({
  paginationOptions,
  context,
  exportEntityType,
  onExportAsk,
  data,
}) => {
  const { t } = useFormatter();
  const classes = useStyles();
  const [open, setOpen] = useState(false);
  const onSubmit = (values, { setSubmitting, resetForm }) => {
    const maxMarkingDefinition = values.maxMarkingDefinition === 'none'
      ? null
      : values.maxMarkingDefinition;
    commitMutation({
      mutation: StixCoreObjectsExportCreationMutation,
      variables: {
        type: exportEntityType,
        format: values.format,
        exportType: 'full',
        maxMarkingDefinition,
        context,
        ...paginationOptions,
      },
      onCompleted: () => {
        setSubmitting(false);
        resetForm();
        if (onExportAsk) onExportAsk();
        setOpen(false);
        MESSAGING$.notifySuccess('Export successfully started');
      },
    });
  };
  const connectorsExport = R.propOr([], 'connectorsForExport', data);
  const exportScopes = R.uniq(
    R.flatten(R.map((c) => c.connector_scope, connectorsExport)),
  );
  const exportConnsPerFormat = scopesConn(connectorsExport);
  // eslint-disable-next-line max-len
  const isExportActive = (format) => R.filter((x) => x.data.active, exportConnsPerFormat[format]).length > 0;
  const isExportPossible = R.filter((x) => isExportActive(x), exportScopes).length > 0;
  return (
    <ExportContext.Consumer>
      {({ selectedIds }) => {
        console.log('selectedIds', selectedIds);
        return (
          <div className={classes.createButton}>
            <Tooltip
              title={
                isExportPossible
                  ? t('Generate an export')
                  : t('No export connector available to generate an export')
              }
              aria-label="generate-export"
            >
        <span>
          <IconButton
            onClick={() => setOpen(true)}
            color="secondary"
            aria-label="Add"
            disabled={!isExportPossible}
            size="large"
          >
            <Add/>
          </IconButton>
        </span>
            </Tooltip>
            <Formik
              enableReinitialize={true}
              initialValues={{
                format: '',
                maxMarkingDefinition: 'none',
              }}
              validationSchema={exportValidation(t)}
              onSubmit={onSubmit}
              onReset={() => setOpen(false)}
            >
              {({ submitForm, handleReset, isSubmitting }) => (
                <Form>
                  <Dialog
                    PaperProps={{ elevation: 1 }}
                    open={open}
                    onClose={() => setOpen(false)}
                    fullWidth={true}
                  >
                    <DialogTitle>{t('Generate an export')}</DialogTitle>
                    <QueryRenderer
                      query={markingDefinitionsLinesSearchQuery}
                      variables={{ first: 200 }}
                      render={({ props }) => {
                        if (props && props.markingDefinitions) {
                          return (
                            <DialogContent>
                              <Field
                                component={SelectField}
                                variant="standard"
                                name="format"
                                label={t('Export format')}
                                fullWidth={true}
                                containerstyle={{ width: '100%' }}
                              >
                                {exportScopes.map((value, i) => (
                                  <MenuItem
                                    key={i}
                                    value={value}
                                    disabled={!isExportActive(value)}
                                  >
                                    {value}
                                  </MenuItem>
                                ))}
                              </Field>
                              <Field
                                component={SelectField}
                                variant="standard"
                                name="maxMarkingDefinition"
                                label={t('Max marking definition level')}
                                fullWidth={true}
                                containerstyle={{
                                  marginTop: 20,
                                  width: '100%',
                                }}
                              >
                                <MenuItem value="none">{t('None')}</MenuItem>
                                {R.map(
                                  (markingDefinition) => (
                                    <MenuItem
                                      key={markingDefinition.node.id}
                                      value={markingDefinition.node.id}
                                    >
                                      {markingDefinition.node.definition}
                                    </MenuItem>
                                  ),
                                  props.markingDefinitions.edges,
                                )}
                              </Field>
                            </DialogContent>
                          );
                        }
                        return <Loader variant="inElement"/>;
                      }}
                    />
                    <DialogActions>
                      <Button onClick={handleReset} disabled={isSubmitting}>
                        {t('Cancel')}
                      </Button>
                      <Button
                        color="secondary"
                        onClick={submitForm}
                        disabled={isSubmitting}
                      >
                        {t('Create')}
                      </Button>
                    </DialogActions>
                  </Dialog>
                </Form>
              )}
            </Formik>
          </div>
        );
      }}
    </ExportContext.Consumer>
  );
};

export default createFragmentContainer(StixCoreObjectsExportCreationComponent, {
  data: graphql`
    fragment StixCoreObjectsExportCreation_data on Query {
      connectorsForExport {
        id
        name
        active
        connector_scope
        updated_at
      }
    }
  `,
});
