import Button from '@common/button/Button';
import { InfoOutlined } from '@mui/icons-material';
import Dialog from '@common/dialog/Dialog';
import DialogActions from '@mui/material/DialogActions';
import MenuItem from '@mui/material/MenuItem';
import Slide from '@mui/material/Slide';
import Tooltip from '@mui/material/Tooltip';
import withStyles from '@mui/styles/withStyles';
import { Field, Form, Formik } from 'formik';
import * as PropTypes from 'prop-types';
import { compose, filter, flatten, fromPairs, includes, map, uniq, zip } from 'ramda';
import React, { Component } from 'react';
import { graphql } from 'react-relay';
import * as Yup from 'yup';
import SelectField from '../../../../components/fields/SelectField';
import inject18n from '../../../../components/i18n';
import { commitMutation, MESSAGING$ } from '../../../../relay/environment';
import { ExportContext } from '../../../../utils/ExportContextProvider';
import { fieldSpacingContainerStyle } from '../../../../utils/field';
import { CONTENT_MAX_MARKINGS_HELPERTEXT, CONTENT_MAX_MARKINGS_TITLE } from '../files/FileManager';
import ObjectMarkingField from '../form/ObjectMarkingField';
import { Stack } from '@mui/material';

const Transition = React.forwardRef((props, ref) => (
  <Slide direction="up" ref={ref} {...props} />
));
Transition.displayName = 'TransitionSlide';

const styles = () => ({
  createButton: {
    position: 'fixed',
    bottom: 30,
    right: 30,
    zIndex: 2000,
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
});

export const StixDomainObjectsExportCreationMutation = graphql`
  mutation StixDomainObjectsExportCreationMutation(
    $format: String!
    $exportType: String!
    $contentMaxMarkings: [String]
    $fileMarkings: [String]
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
      contentMaxMarkings: $contentMaxMarkings
      fileMarkings: $fileMarkings
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
  type: Yup.string().required(t('This field is required')),
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

class StixDomainObjectsExportCreation extends Component {
  constructor(props) {
    super(props);
    this.state = { selectedContentMaxMarkingsIds: [] };
  }

  handleSelectedContentMaxMarkingsChange(values) {
    this.setState({ selectedContentMaxMarkingsIds: values.map(({ value }) => value) });
  }

  onSubmit(selectedIds, values, { setSubmitting, resetForm }) {
    const { paginationOptions, exportContext } = this.props;

    const contentMaxMarkings = values.contentMaxMarkings.map(({ value }) => value);
    const fileMarkings = values.fileMarkings.map(({ value }) => value);

    commitMutation({
      mutation: StixDomainObjectsExportCreationMutation,
      variables: {
        format: values.format,
        exportType: values.type,
        contentMaxMarkings,
        fileMarkings,
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
    const { t, exportScopes, isExportActive } = this.props;
    const availableFormat = exportScopes;
    return (
      <ExportContext.Consumer>
        {({ selectedIds }) => {
          return (
            <Formik
              enableReinitialize={true}
              initialValues={{
                format: '',
                type: 'simple',
                maxMarkingDefinition: 'none',
                contentMaxMarkings: [],
                fileMarkings: [],
              }}
              validationSchema={exportValidation(t)}
              onSubmit={this.onSubmit.bind(this, selectedIds)}
              onReset={() => this.props.onClose()}
            >
              {({ submitForm, resetForm, isSubmitting, setFieldValue }) => (
                <Form>
                  <Dialog
                    open={this.props.open}
                    onClose={this.props.onClose}
                    data-testid="StixDomainObjectsExportCreationDialog"
                    title={(
                      <Stack direction="row" gap={1} alignContent="center">
                        {t('Generate an export')}
                        <Tooltip title={t('Your max shareable markings will be applied to the content max markings')}>
                          <InfoOutlined color="primary" />
                        </Tooltip>
                      </Stack>
                    )}
                  >
                    <Field
                      component={SelectField}
                      variant="standard"
                      name="format"
                      label={t('Export format')}
                      fullWidth={true}
                      containerstyle={{ width: '100%' }}
                    >
                      {availableFormat.map((value, i) => (
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
                    <ObjectMarkingField
                      name="contentMaxMarkings"
                      label={t(CONTENT_MAX_MARKINGS_TITLE)}
                      onChange={(_, values) => this.handleSelectedContentMaxMarkingsChange(values)}
                      style={fieldSpacingContainerStyle}
                      setFieldValue={setFieldValue}
                      limitToMaxSharing
                      helpertext={t(CONTENT_MAX_MARKINGS_HELPERTEXT)}
                    />
                    <ObjectMarkingField
                      name="fileMarkings"
                      label={t('File marking definition levels')}
                      filterTargetIds={this.state.selectedContentMaxMarkingsIds}
                      style={fieldSpacingContainerStyle}
                      setFieldValue={setFieldValue}
                    />
                    <DialogActions>
                      <Button
                        variant="secondary"
                        onClick={() => {
                          this.props.onClose();
                          resetForm();
                        }}
                        disabled={isSubmitting}
                      >
                        {t('Cancel')}
                      </Button>
                      <Button
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
          );
        }}
      </ExportContext.Consumer>
    );
  }
}

StixDomainObjectsExportCreation.propTypes = {
  classes: PropTypes.object.isRequired,
  t: PropTypes.func,
  data: PropTypes.object,
  exportContext: PropTypes.object,
  paginationOptions: PropTypes.object,
  onExportAsk: PropTypes.func,
  open: PropTypes.bool,
};

export default compose(
  inject18n,
  withStyles(styles),
)(StixDomainObjectsExportCreation);
