import React, { useEffect } from 'react';
import * as PropTypes from 'prop-types';
import { createFragmentContainer, graphql } from 'react-relay';
import { Field, Form, Formik } from 'formik';
import withStyles from '@mui/styles/withStyles';
import * as Yup from 'yup';
import * as R from 'ramda';
import Alert from '@mui/material/Alert';
import AlertTitle from '@mui/material/AlertTitle';
import FormControlLabel from '@mui/material/FormControlLabel';
import Switch from '@mui/material/Switch';
import ObjectMembersField from '../../common/form/ObjectMembersField';
import inject18n from '../../../../components/i18n';
import { commitMutation } from '../../../../relay/environment';
import TextField from '../../../../components/TextField';
import Filters from '../../common/lists/Filters';
import { deserializeFilterGroupForFrontend, serializeFilterGroupForBackend } from '../../../../utils/filters/filtersUtils';
import FilterIconButton from '../../../../components/FilterIconButton';
import { fieldSpacingContainerStyle } from '../../../../utils/field';
import { convertAuthorizedMembers } from '../../../../utils/edition';
import useFiltersState from '../../../../utils/filters/useFiltersState';

const styles = (theme) => ({
  header: {
    backgroundColor: theme.palette.background.nav,
    padding: '20px 0px 20px 60px',
  },
  closeButton: {
    position: 'absolute',
    top: 12,
    left: 5,
    color: 'inherit',
  },
  importButton: {
    position: 'absolute',
    top: 15,
    right: 20,
  },
  container: {
    padding: '10px 20px 20px 20px',
  },
  appBar: {
    width: '100%',
    zIndex: theme.zIndex.drawer + 1,
    borderBottom: '1px solid #5c5c5c',
  },
  title: {
    float: 'left',
  },
  alert: {
    width: '100%',
    marginTop: 20,
  },
  message: {
    width: '100%',
    overflow: 'hidden',
  },
});

const taxiiCollectionMutationFieldPatch = graphql`
  mutation TaxiiCollectionEditionFieldPatchMutation(
    $id: ID!
    $input: [EditInput]!
  ) {
    taxiiCollectionEdit(id: $id) {
      fieldPatch(input: $input) {
        ...TaxiiCollectionEdition_taxiiCollection
      }
    }
  }
`;

const taxiiCollectionValidation = (t) => Yup.object().shape({
  name: Yup.string().required(t('This field is required')),
  description: Yup.string().nullable(),
  authorized_members: Yup.array().nullable(),
  taxii_public: Yup.bool().nullable(),
});

const TaxiiCollectionEditionContainer = (props) => {
  const { t, classes, taxiiCollection } = props;
  const initialValues = {
    name: taxiiCollection.name,
    description: taxiiCollection.description,
    taxii_public: taxiiCollection.taxii_public,
    authorized_members: convertAuthorizedMembers(taxiiCollection),
  };
  const [filters, helpers] = useFiltersState(deserializeFilterGroupForFrontend(props.taxiiCollection.filters));
  const handleSubmitField = (name, value) => {
    taxiiCollectionValidation(props.t)
      .validateAt(name, { [name]: value })
      .then(() => {
        commitMutation({
          mutation: taxiiCollectionMutationFieldPatch,
          variables: {
            id: props.taxiiCollection.id,
            input: { key: name, value: value || '' },
          },
        });
      })
      .catch(() => false);
  };

  const handleSubmitFieldOptions = (name, value) => taxiiCollectionValidation(t)
    .validateAt(name, { [name]: value })
    .then(() => {
      commitMutation({
        mutation: taxiiCollectionMutationFieldPatch,
        variables: {
          id: props.taxiiCollection.id,
          input: { key: name, value: value?.map(({ value: v }) => v) ?? '' },
        },
      });
    })
    .catch(() => false);

  useEffect(() => {
    const jsonFilters = serializeFilterGroupForBackend(filters);
    const variables = {
      id: props.taxiiCollection.id,
      input: { key: 'filters', value: jsonFilters },
    };
    commitMutation({
      mutation: taxiiCollectionMutationFieldPatch,
      variables,
    });
  }, [filters]);
  return (
    <Formik
      enableReinitialize={true}
      initialValues={initialValues}
      validationSchema={taxiiCollectionValidation(t)}
    >
      {() => (
        <Form style={{ margin: '20px 0 20px 0' }}>
          <Field
            component={TextField}
            variant="standard"
            name="name"
            label={t('Name')}
            fullWidth={true}
            onSubmit={handleSubmitField}
          />
          <Field
            component={TextField}
            variant="standard"
            name="description"
            label={t('Description')}
            fullWidth={true}
            style={{ marginTop: 20 }}
            onSubmit={handleSubmitField}
          />
          <Alert
            icon={false}
            classes={{ root: classes.alert, message: classes.message }}
            severity="warning"
            variant="outlined"
            style={{ position: 'relative' }}
          >
            <AlertTitle>
              {t('Make this taxii collection public and available to anyone')}
            </AlertTitle>
            <FormControlLabel
              control={<Switch defaultChecked={initialValues.taxii_public}/>}
              style={{ marginLeft: 1 }}
              onChange={(_, checked) => handleSubmitField('taxii_public', checked.toString())}
              label={t('Public taxii collection')}
            />
            {!initialValues.taxii_public && (
              <ObjectMembersField
                label={'Accessible for'}
                style={fieldSpacingContainerStyle}
                onChange={handleSubmitFieldOptions}
                multiple={true}
                helpertext={t('Let the field empty to grant all authenticated users')}
                name="authorized_members"
              />
            )}
          </Alert>
          <div style={{ paddingTop: 35 }}>
            <Filters
              availableFilterKeys={[
                'entity_type',
                'workflow_id',
                'objectAssignee',
                'objects',
                'objectMarking',
                'objectLabel',
                'creator_id',
                'createdBy',
                'priority',
                'severity',
                'x_opencti_score',
                'x_opencti_detection',
                'x_opencti_main_observable_type',
                'revoked',
                'confidence',
                'indicator_types',
                'pattern_type',
                'fromId',
                'toId',
                'fromTypes',
                'toTypes',
              ]}
              helpers={helpers}
              noDirectFilters={true}
            />
          </div>
          <div className="clearfix"/>
          <FilterIconButton
            filters={filters}
            helpers={helpers}
            styleNumber={2}
            redirection
          />
        </Form>
      )}
    </Formik>
  );
};

TaxiiCollectionEditionContainer.propTypes = {
  handleClose: PropTypes.func,
  classes: PropTypes.object,
  taxiiCollection: PropTypes.object,
  theme: PropTypes.object,
  t: PropTypes.func,
};

const TaxiiCollectionEditionFragment = createFragmentContainer(
  TaxiiCollectionEditionContainer,
  {
    taxiiCollection: graphql`
      fragment TaxiiCollectionEdition_taxiiCollection on TaxiiCollection {
        id
        name
        description
        filters
        taxii_public
        authorized_members {
          id
          name
        }
      }
    `,
  },
);

export default R.compose(
  inject18n,
  withStyles(styles, { withTheme: true }),
)(TaxiiCollectionEditionFragment);
