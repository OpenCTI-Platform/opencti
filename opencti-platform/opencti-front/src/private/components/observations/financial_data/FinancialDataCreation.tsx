import { makeStyles } from '@mui/styles';
import React, { FunctionComponent, useState } from 'react';
import { graphql } from 'react-relay';
import { Theme } from 'src/components/Theme';
import { useFormatter } from 'src/components/i18n';
import { QueryRenderer, commitMutation, defaultCommitMutation, handleErrorInForm } from 'src/relay/environment';
import useVocabularyCategory from 'src/utils/hooks/useVocabularyCategory';
import { insertNode } from 'src/utils/store';
import * as Yup from 'yup';
import { Field, Form, Formik, FormikErrors } from 'formik';
import { TextField } from 'formik-mui';
import MarkdownField from 'src/components/fields/MarkdownField';
import OpenVocabField from '@components/common/form/OpenVocabField';
import DateTimePickerField from 'src/components/DateTimePickerField';
import SwitchField from 'src/components/fields/SwitchField';
import ArtifactField from '@components/common/form/ArtifactField';
import CreatedByField from '@components/common/form/CreatedByField';
import ObjectLabelField from '@components/common/form/ObjectLabelField';
import ObjectMarkingField from '@components/common/form/ObjectMarkingField';
import { ExternalReferencesField } from '@components/common/form/ExternalReferencesField';
import { Button, Dialog, DialogContent, DialogTitle, Drawer, Fab, IconButton, List, ListItemButton, ListItemText, Typography } from '@mui/material';
import { Add } from '@mui/icons-material';
import { Close } from 'mdi-material-ui';
import { convertMarking } from 'src/utils/edition';
import { fieldSpacingContainerStyle } from 'src/utils/field';
import { RecordSourceSelectorProxy } from 'relay-runtime';
import useAttributes from '../../../../utils/hooks/useAttributes';
import { FinancialDataLinesPaginationQuery$variables } from './__generated__/FinancialDataLinesPaginationQuery.graphql';
import { stixCyberObservablesLinesAttributesQuery, stixCyberObservablesLinesSubTypesQuery } from '../stix_cyber_observables/StixCyberObservablesLines';
import { StixCyberObservablesLinesAttributesQuery$data } from '../stix_cyber_observables/__generated__/StixCyberObservablesLinesAttributesQuery.graphql';
import { StixCyberObservablesLinesSubTypes } from './FinancialDataRightBar';

const useStyles = makeStyles<Theme>((theme) => ({
  drawerPaper: {
    minHeight: '100vh',
    width: '50%',
    position: 'fixed',
    transition: theme.transitions.create('width', {
      easing: theme.transitions.easing.sharp,
      duration: theme.transitions.duration.enteringScreen,
    }),
    padding: 0,
  },
  createButton: {
    position: 'fixed',
    bottom: 30,
    right: 280,
    transition: theme.transitions.create('right', {
      easing: theme.transitions.easing.sharp,
      duration: theme.transitions.duration.enteringScreen,
    }),
  },
  createButtonContextual: {
    position: 'fixed',
    bottom: 30,
    right: 30,
    zIndex: 2000,
  },
  buttons: {
    marginTop: 20,
    textAlign: 'right',
  },
  button: {
    marginLeft: theme.spacing(2),
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
  container: {
    padding: '10px 20px 20px 20px',
  },
}));

const financialDataMutation = graphql`
  mutation FinancialDataCreationMutation(
    $type: String!
    $x_opencti_score: Int
    $x_opencti_description: String
    $createIndicator: Boolean
    $createdBy: String
    $objectMarking: [String]
    $objectLabel: [String]
    $externalReferences: [String]
    $FinancialAccount: FinancialAccountAddInput
    $FinancialAsset: FinancialAssetAddInput
    $FinancialTransaction: FinancialTransactionAddInput
  ) {
    stixCyberObservableAdd(
      type: $type
      x_opencti_score: $x_opencti_score
      x_opencti_description: $x_opencti_description
      createIndicator: $createIndicator
      createdBy: $createdBy
      objectMarking: $objectMarking
      objectLabel: $objectLabel
      externalReferences: $externalReferences
      FinancialAccount: $FinancialAccount
      FinancialAsset: $FinancialAsset
      FinancialTransaction: $FinancialTransaction
    ) {
      id
      standard_id
      entity_type
      parent_types
      observable_value
      x_opencti_description
      created_at
      createdBy {
        ... on Identity {
          id
          name
          entity_type
        }
      }
      objectMarking {
        id
        definition_type
        definition
        x_opencti_order
        x_opencti_color
      }
      objectLabel {
        id
        value
        color
      }
    }
  }
`;

const financialDataValidation = () => Yup.object().shape({
  x_opencti_score: Yup.number().nullable(),
  x_opencti_description: Yup.string().nullable(),
  createIndicator: Yup.boolean(),
});

interface StateProps {
  open: boolean
  type: string
}

interface FinancialDataCreationProps {
  contextual: boolean
  open: boolean
  type: string
  speeddial: boolean
  paginationKey: string
  paginationOptions: FinancialDataLinesPaginationQuery$variables
  display?: boolean
  handleClose?: () => void
  defaultCreatedBy?: { id: string; name: string }
  defaultMarkingDefinitions?: { value: string; label: string }[]
}

const FinancialDataCreation: FunctionComponent<FinancialDataCreationProps> = ({
  contextual,
  open,
  type,
  display,
  speeddial,
  paginationKey,
  paginationOptions,
  handleClose = () => {},
  defaultCreatedBy = null,
  defaultMarkingDefinitions = null,
}) => {
  const classes = useStyles();
  const { t_i18n } = useFormatter();
  const { isVocabularyField, fieldToCategory } = useVocabularyCategory();
  const [status, setStatus] = useState<StateProps>({ open: false, type: type ?? '' });

  const handleOpen = () => setStatus({ open: true, type: status.type });
  const localHandleClose = () => setStatus({ open: false, type: '' });
  const selectType = (selected: string) => setStatus({ open: status.open, type: selected });

  const onSubmit = (
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    values: any,
    { setSubmitting, setErrors, resetForm }: {
      setSubmitting: (isSubmitting: boolean) => void
      setErrors: (errors: FormikErrors<unknown>) => void
      resetForm: (nextState?: Partial<FormikErrors<unknown>> | undefined) => void
    },
  ) => {
    const sanitizedValues = { ...values };
    const removeFields = [
      'x_opencti_description',
      'x_opencti_score',
      'createdBy',
      'objectMarking',
      'objectLabel',
      'externalReferences',
      'createIndicator',
    ];
    for (const field of removeFields) {
      delete sanitizedValues[field];
    }
    const finalValues = {
      type: status.type,
      x_opencti_description:
        values.x_opencti_description.length > 0
          ? values.x_opencti_description
          : null,
      x_opencti_score: parseInt(values.x_opencti_score, 10),
      createdBy: values.createdBy?.value,
      objectMarking: values.objectMarking?.value,
      objectLabel: values.objectLabel?.value,
      externalReferences: values.externalReferences.value,
      createIndicator: values.createIndicator,
      [status.type.replace(/(?:^|-|_)(\w)/g, (_, letter) => letter.toUpperCase())]: {
        ...sanitizedValues,
        obsContent: values.obsContent?.value,
      },
    };
    commitMutation({
      ...defaultCommitMutation,
      mutation: financialDataMutation,
      variables: finalValues,
      updater: (store: RecordSourceSelectorProxy) => insertNode(
        store,
        paginationKey,
        paginationOptions,
        'stixCyberObservableAdd',
      ),
      onError: (error: Error) => {
        handleErrorInForm(error, setErrors);
        setSubmitting(false);
      },
      setSubmitting,
      onCompleted: () => {
        setSubmitting(false);
        resetForm();
        localHandleClose();
      },
    });
  };

  const onReset = () => {
    if (speeddial) {
      handleClose();
    } else {
      localHandleClose();
    }
  };

  const renderList = () => {
    return (
      <QueryRenderer
        query={stixCyberObservablesLinesSubTypesQuery}
        variables={{ type: 'Stix-Cyber-Observable', search: 'Financial' }}
        render={({ props }: { props: StixCyberObservablesLinesSubTypes }) => {
          if (props && props.subTypes) {
            const subTypesEdges = [...props.subTypes.edges];
            const translatedOrderedList = subTypesEdges
              .sort(({ node: a }, { node: b }) => (a.label < b.label ? -1 : 1))
              .map(({ node }) => ({ ...node, tlabel: t_i18n(`entity_${node.label}`) }));
            return (
              <List>
                {translatedOrderedList.map((subType) => (
                  <ListItemButton
                    key={subType.label}
                    divider={true}
                    dense={true}
                    onClick={() => selectType(subType.label)}
                    data-testid={subType.label}
                  >
                    <ListItemText primary={subType.tlabel} />
                  </ListItemButton>
                ))}
              </List>
            );
          }
          return <div />;
        }}
      />
    );
  };

  const { booleanAttributes, dateAttributes, numberAttributes, ignoredAttributes } = useAttributes();
  const renderForm = () => {
    return (
      <QueryRenderer
        query={stixCyberObservablesLinesAttributesQuery}
        variables={{ elementType: [status.type] }}
        render={({ props }: { props: StixCyberObservablesLinesAttributesQuery$data }) => {
          if (props && props.schemaAttributeNames) {
            const baseCreatedBy = defaultCreatedBy
              ? { value: defaultCreatedBy.id, label: defaultCreatedBy.name }
              : undefined;
            const baseMarkingDefinitions = (
              defaultMarkingDefinitions ?? []
            ).map((n) => convertMarking(n));
            const initialValues: Record<string, unknown> = {
              x_opencti_description: '',
              x_opencti_score: 50,
              createdBy: baseCreatedBy,
              objectMarking: baseMarkingDefinitions,
              objectLabel: [],
              externalReferences: [],
              createIndicator: false,
              file: undefined,
            };
            const attributes = props.schemaAttributeNames.edges
              .map((n) => n.node)
              .filter((n) => !ignoredAttributes.includes(n.value)
                && !n.value.startsWith('i_'));
            for (const attribute of attributes) {
              if (isVocabularyField(status.type, attribute.value)) {
                initialValues[attribute.value] = null;
              } else if (dateAttributes.includes(attribute.value)) {
                initialValues[attribute.value] = null;
              } else if (booleanAttributes.includes(attribute.value)) {
                initialValues[attribute.value] = false;
              } else {
                initialValues[attribute.value] = '';
              }
            }
            return (
              <Formik
                initialValues={initialValues}
                validationSchema={financialDataValidation()}
                onSubmit={onSubmit}
                onReset={onReset}
              >
                {({
                  submitForm,
                  handleReset,
                  isSubmitting,
                  setFieldValue,
                  values,
                }) => (
                  <Form
                    style={{
                      margin: contextual ? '10px 0 0 0' : '20px 0 20px 0',
                    }}
                  >
                    <div>
                      <Field
                        component={TextField}
                        variant="standard"
                        name="x_opencti_score"
                        label={t_i18n('Score')}
                        fullWidth={true}
                        type="number"
                      />
                      <Field
                        component={MarkdownField}
                        name="x_opencti_description"
                        label={t_i18n('Description')}
                        fullWidth={true}
                        multiline={true}
                        rows="4"
                        style={{ marginTop: 20 }}
                      />
                      {attributes.map((attribute) => {
                        if (attribute.value === 'hashes') {
                          return (
                            <div key={attribute.value}>
                              <Field
                                component={TextField}
                                variant="standard"
                                name="hashes.MD5"
                                label={t_i18n('hash_md5')}
                                fullWidth={true}
                                style={{ marginTop: 20 }}
                              />
                              <Field
                                component={TextField}
                                variant="standard"
                                name="hashes_SHA-1"
                                label={t_i18n('hash_sha-1')}
                                fullWidth={true}
                                style={{ marginTop: 20 }}
                              />
                              <Field
                                component={TextField}
                                variant="standard"
                                name="hashes_SHA-256"
                                label={t_i18n('hash_sha-256')}
                                fullWidth={true}
                                style={{ marginTop: 20 }}
                              />
                              <Field
                                component={TextField}
                                variant="standard"
                                name="hashes_SHA-512"
                                label={t_i18n('hash_sha-512')}
                                fullWidth={true}
                                style={{ marginTop: 20 }}
                              />
                            </div>
                          );
                        }
                        if (isVocabularyField(status.type, attribute.value)) {
                          return (
                            <OpenVocabField
                              key={attribute.value}
                              label={t_i18n(attribute.value)}
                              type={fieldToCategory(
                                status.type,
                                attribute.value,
                              ) ?? ''}
                              name={attribute.value}
                              onChange={(name, value) => setFieldValue(name, value)
                              }
                              containerStyle={fieldSpacingContainerStyle}
                              multiple={false}
                            />
                          );
                        }
                        if (dateAttributes.includes(attribute.value)) {
                          return (
                            <Field
                              component={DateTimePickerField}
                              key={attribute.value}
                              name={attribute.value}
                              withSeconds={true}
                              textFieldProps={{
                                label: attribute.value,
                                variant: 'standard',
                                fullWidth: true,
                                style: { marginTop: 20 },
                              }}
                            />
                          );
                        }
                        if (numberAttributes.includes(attribute.value)) {
                          return (
                            <Field
                              component={TextField}
                              variant="standard"
                              key={attribute.value}
                              name={attribute.value}
                              label={attribute.value}
                              fullWidth={true}
                              type="number"
                              style={{ marginTop: 20 }}
                            />
                          );
                        }
                        if (booleanAttributes.includes(attribute.value)) {
                          return (
                            <Field
                              component={SwitchField}
                              type="checkbox"
                              key={attribute.value}
                              name={attribute.value}
                              label={attribute.value}
                              fullWidth={true}
                              containerstyle={{ marginTop: 20 }}
                            />
                          );
                        }
                        if (attribute.value === 'obsContent') {
                          return (
                            <ArtifactField
                              key={attribute.value}
                              attributeName={attribute.value}
                              onChange={setFieldValue}
                            />
                          );
                        }
                        return (
                          <Field
                            component={TextField}
                            variant="standard"
                            key={attribute.value}
                            name={attribute.value}
                            label={attribute.value}
                            fullWidth={true}
                            style={{ marginTop: 20 }}
                          />
                        );
                      })}
                    </div>
                    <CreatedByField
                      name="createdBy"
                      style={fieldSpacingContainerStyle}
                      setFieldValue={setFieldValue}
                    />
                    <ObjectLabelField
                      name="objectLabel"
                      style={fieldSpacingContainerStyle}
                      setFieldValue={setFieldValue}
                      values={values.objectLabel}
                    />
                    <ObjectMarkingField
                      name="objectMarking"
                      style={fieldSpacingContainerStyle}
                    />
                    <ExternalReferencesField
                      name="externalReferences"
                      style={fieldSpacingContainerStyle}
                      setFieldValue={setFieldValue}
                      values={values.externalReferences}
                    />
                    <Field
                      component={SwitchField}
                      type="checkbox"
                      name="createIndicator"
                      label={t_i18n('Create an indicator from this observable')}
                      containerstyle={{ marginTop: 20 }}
                    />
                    <div className={classes.buttons}>
                      <Button
                        variant={contextual ? 'text' : 'contained'}
                        onClick={handleReset}
                        disabled={isSubmitting}
                        classes={{ root: classes.button }}
                      >
                        {t_i18n('Cancel')}
                      </Button>
                      <Button
                        variant={contextual ? 'text' : 'contained'}
                        color="secondary"
                        onClick={submitForm}
                        disabled={isSubmitting}
                        classes={{ root: classes.button }}
                      >
                        {t_i18n('Create')}
                      </Button>
                    </div>
                  </Form>
                )}
              </Formik>
            );
          }
          return <div />;
        }}
      />
    );
  };

  const renderClassic = () => {
    return (
      <div>
        <Fab
          onClick={handleOpen}
          color="secondary"
          aria-label="Add"
          className={classes.createButton}
        >
          <Add />
        </Fab>
        <Drawer
          open={status.open}
          anchor="right"
          sx={{ zIndex: 1202 }}
          elevation={1}
          classes={{ paper: classes.drawerPaper }}
          onClose={localHandleClose}
        >
          <div className={classes.header}>
            <IconButton
              aria-label="Close"
              className={classes.closeButton}
              onClick={localHandleClose}
              size="large"
              color="primary"
            >
              <Close fontSize="small" color="primary" />
            </IconButton>
            <Typography variant="h6">{t_i18n('Create financial data')}</Typography>
          </div>
          <div className={classes.container}>
            {!status.type ? renderList() : renderForm()}
          </div>
        </Drawer>
      </div>
    );
  };

  const renderContextual = () => {
    return (
      <div style={{ display: display ? 'block' : 'none' }}>
        {!speeddial && (
          <Fab
            onClick={handleOpen}
            color="secondary"
            aria-label="Add"
            className={classes.createButtonContextual}
          >
            <Add />
          </Fab>
        )}
        <Dialog
          open={speeddial ? open : status.open}
          PaperProps={{ elevation: 1 }}
          onClose={speeddial ? handleClose : localHandleClose}
          fullWidth={true}
        >
          <DialogTitle>{t_i18n('Create financial data')}</DialogTitle>
          <DialogContent style={{ paddingTop: 0 }}>
            {!status.type ? renderList() : renderForm()}
          </DialogContent>
        </Dialog>
      </div>
    );
  };

  if (contextual) {
    return renderContextual();
  }
  return renderClassic();
};

export default FinancialDataCreation;
