import React, { Component } from 'react';
import * as PropTypes from 'prop-types';
import { compose, filter, flatten, fromPairs, includes, map, propOr, uniq, zip } from 'ramda';
import Dialog from '@mui/material/Dialog';
import DialogTitle from '@mui/material/DialogTitle';
import DialogContent from '@mui/material/DialogContent';
import DialogActions from '@mui/material/DialogActions';
import Button from '@mui/material/Button';
import Slide from '@mui/material/Slide';
import { Add } from '@mui/icons-material';
import { createFragmentContainer, graphql } from 'react-relay';
import { Field, Form, Formik } from 'formik';
import MenuItem from '@mui/material/MenuItem';
import * as Yup from 'yup';
import Tooltip from '@mui/material/Tooltip';
import inject18n from '../../../../components/i18n';
import { commitMutation, MESSAGING$, QueryRenderer } from '../../../../relay/environment';
import { markingDefinitionsLinesSearchQuery } from '../../settings/marking_definitions/MarkingDefinitionsLines';
import SelectField from '../../../../components/SelectField';
import Loader from '../../../../components/Loader';
import { ExportContext } from '../../../../utils/ExportContextProvider';
import { fieldSpacingContainerStyle } from '../../../../utils/field';

const Transition = React.forwardRef((props, ref) => (
  <Slide direction="up" ref={ref} {...props} />
));
Transition.displayName = 'TransitionSlide';

export const StixDomainObjectsExportCreationMutation = graphql`
  mutation StixDomainObjectsExportCreationMutation(
    $format: String!
    $exportType: String!
    $maxMarkingDefinition: String
    $exportContext: ExportContext
    $search: String
    $orderBy: StixDomainObjectsOrdering
    $orderMode: OrderingMode
    $filters: FilterGroup
    $relationship_type: [String]
    $selectedIds: [String]
  ) {
    stixDomainObjectsExportAsk(
      format: $format
      exportType: $exportType
      maxMarkingDefinition: $maxMarkingDefinition
      exportContext: $exportContext
      search: $search
      orderBy: $orderBy
      orderMode: $orderMode
      filters: $filters
      relationship_type: $relationship_type
      selectedIds: $selectedIds
    ) {
      id
    }
  }
`;

const exportValidation = (t) => Yup.object().shape({
  format: Yup.string().required(t('This field is required')),
});

export const scopesConn = (exportConnectors) => {
  const scopes = uniq(flatten(exportConnectors.map((c) => c.connector_scope)));
  const connectors = scopes.map((s) => {
    const filteredConnectors = filter(
      (e) => includes(s, e.connector_scope),
      exportConnectors,
    );
    return map(
      (x) => ({ data: { name: x.name, active: x.active } }),
      filteredConnectors,
    );
  });
  const zipped = zip(scopes, connectors);
  return fromPairs(zipped);
};

class StixDomainObjectsExportCreationComponent extends Component {
  constructor(props) {
    super(props);
    this.state = { open: false };
  }

  handleOpen() {
    this.setState({ open: true });
  }

  handleClose() {
    this.setState({ open: false });
  }

  onSubmit(selectedIds, values, { setSubmitting, resetForm }) {
    const { paginationOptions, exportContext } = this.props;
    const maxMarkingDefinition = values.maxMarkingDefinition === 'none'
      ? null
      : values.maxMarkingDefinition;
    commitMutation({
      mutation: StixDomainObjectsExportCreationMutation,
      variables: {
        format: values.format,
        exportType: values.type,
        maxMarkingDefinition,
        exportContext,
        ...paginationOptions,
        selectedIds,
      },
      onCompleted: () => {
        setSubmitting(false);
        resetForm();
        if (this.props.onExportAsk) this.props.onExportAsk();
        this.handleClose();
        MESSAGING$.notifySuccess('Export successfully started');
      },
    });
  }

  render() {
    const { t, data } = this.props;
    const connectorsExport = propOr([], 'connectorsForExport', data);
    const exportScopes = uniq(
      flatten(map((c) => c.connector_scope, connectorsExport)),
    );
    const exportConnsPerFormat = scopesConn(connectorsExport);
    const isExportActive = (format) => filter((x) => x.data.active, exportConnsPerFormat[format]).length > 0;
    const isExportPossible = filter((x) => isExportActive(x), exportScopes).length > 0;
    return (
      <ExportContext.Consumer>
        {({ selectedIds }) => {
          return (
            <>
              <Tooltip
                title={
                  isExportPossible
                    ? t('Generate an export')
                    : t('No export connector available to generate an export')
                }
                aria-label="generate-export"
              >
                <span>
                  <Button
                    onClick={this.handleOpen.bind(this)}
                    color="primary"
                    size="small"
                    variant="contained"
                    aria-label={t('Add')}
                    disabled={!isExportPossible}
                  >
                    {t('Add')} <Add />
                  </Button>
                </span>
              </Tooltip>
              <Formik
                enableReinitialize={true}
                initialValues={{
                  format: '',
                  type: 'simple',
                  maxMarkingDefinition: 'none',
                }}
                validationSchema={exportValidation(t)}
                onSubmit={this.onSubmit.bind(this, selectedIds)}
                onReset={this.handleClose.bind(this)}
              >
                {({ submitForm, handleReset, isSubmitting }) => (
                  <Form>
                    <Dialog
                      PaperProps={{ elevation: 1 }}
                      open={this.state.open}
                      onClose={this.handleClose.bind(this)}
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
                                  name="type"
                                  label={t('Export type')}
                                  fullWidth={true}
                                  containerstyle={fieldSpacingContainerStyle}
                                >
                                  <MenuItem value="simple">
                                    {t('Simple export (just the entity)')}
                                  </MenuItem>
                                  <MenuItem value="full">
                                    {t(
                                      'Full export (entity and first neighbours)',
                                    )}
                                  </MenuItem>
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
                                  {map(
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
                          return <Loader variant="inElement" />;
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
            </>
          );
        }}
      </ExportContext.Consumer>
    );
  }
}

const StixDomainObjectsExportCreations = createFragmentContainer(
  StixDomainObjectsExportCreationComponent,
  {
    data: graphql`
      fragment StixDomainObjectsExportCreation_data on Query {
        connectorsForExport {
          id
          name
          active
          connector_scope
          updated_at
        }
      }
    `,
  },
);

StixDomainObjectsExportCreations.propTypes = {
  t: PropTypes.func,
  data: PropTypes.object,
  exportContext: PropTypes.object,
  paginationOptions: PropTypes.object,
  onExportAsk: PropTypes.func,
};

export default compose(
  inject18n,
)(StixDomainObjectsExportCreations);
