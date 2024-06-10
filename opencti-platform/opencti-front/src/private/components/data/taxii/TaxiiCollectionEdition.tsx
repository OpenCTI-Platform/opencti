import React, { FunctionComponent, useEffect } from 'react';
import { createFragmentContainer, graphql } from 'react-relay';
import { Field, Form, Formik } from 'formik';
import * as Yup from 'yup';
import Alert from '@mui/material/Alert';
import AlertTitle from '@mui/material/AlertTitle';
import FormControlLabel from '@mui/material/FormControlLabel';
import Switch from '@mui/material/Switch';
import Box from '@mui/material/Box';
import makeStyles from '@mui/styles/makeStyles';
import { Option } from '@components/common/form/ReferenceField';
import { TaxiiCollectionEdition_taxiiCollection$data } from '@components/data/taxii/__generated__/TaxiiCollectionEdition_taxiiCollection.graphql';
import { FormikConfig } from 'formik/dist/types';
import ObjectMembersField from '../../common/form/ObjectMembersField';
import { useFormatter } from '../../../../components/i18n';
import { commitMutation } from '../../../../relay/environment';
import TextField from '../../../../components/TextField';
import Filters from '../../common/lists/Filters';
import { useAvailableFilterKeysForEntityTypes, deserializeFilterGroupForFrontend, serializeFilterGroupForBackend } from '../../../../utils/filters/filtersUtils';
import FilterIconButton from '../../../../components/FilterIconButton';
import { fieldSpacingContainerStyle } from '../../../../utils/field';
import { convertAuthorizedMembers } from '../../../../utils/edition';
import useFiltersState from '../../../../utils/filters/useFiltersState';

// Deprecated - https://mui.com/system/styles/basics/
// Do not use it for new code.
const useStyles = makeStyles(() => ({
  alert: {
    width: '100%',
    marginTop: 20,
  },
  message: {
    width: '100%',
    overflow: 'hidden',
  },
}));

interface TaxiiCollectionCreationForm {
  authorized_members: Option[]
  taxii_public?: boolean | null
  name: string | null
  description: string | null
}

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

const taxiiCollectionValidation = (requiredSentence: string) => Yup.object().shape({
  name: Yup.string().required(requiredSentence),
  description: Yup.string().nullable(),
  authorized_members: Yup.array().nullable(),
  taxii_public: Yup.bool().nullable(),
});

const TaxiiCollectionEditionContainer: FunctionComponent<{ taxiiCollection: TaxiiCollectionEdition_taxiiCollection$data }> = ({ taxiiCollection }) => {
  const { t_i18n } = useFormatter();
  const classes = useStyles();
  const initialValues = {
    name: taxiiCollection.name ?? '',
    description: taxiiCollection.description ?? '',
    taxii_public: taxiiCollection.taxii_public,
    authorized_members: convertAuthorizedMembers(taxiiCollection),
  };
  const [filters, helpers] = useFiltersState(deserializeFilterGroupForFrontend(taxiiCollection.filters) ?? undefined);
  const handleSubmitField = (name: string, value: Option[] | string) => {
    taxiiCollectionValidation(t_i18n('This field is required'))
      .validateAt(name, { [name]: value })
      .then(() => {
        commitMutation({
          mutation: taxiiCollectionMutationFieldPatch,
          variables: {
            id: taxiiCollection.id,
            input: { key: name, value: value || '' },
          },
          setSubmitting: undefined,
          onCompleted: undefined,
          onError: undefined,
          optimisticResponse: undefined,
          optimisticUpdater: undefined,
          updater: undefined,
        });
      })
      .catch(() => false);
  };

  const handleSubmitFieldOptions = (name: string, value: Option[]) => taxiiCollectionValidation(t_i18n('This field is required'))
    .validateAt(name, { [name]: value })
    .then(() => {
      commitMutation({
        mutation: taxiiCollectionMutationFieldPatch,
        variables: {
          id: taxiiCollection.id,
          input: { key: name, value: value?.map(({ value: v }) => v) ?? '' },
        },
        setSubmitting: undefined,
        onCompleted: undefined,
        onError: undefined,
        optimisticResponse: undefined,
        optimisticUpdater: undefined,
        updater: undefined,
      });
    })
    .catch(() => false);

  useEffect(() => {
    const jsonFilters = serializeFilterGroupForBackend(filters);
    const variables = {
      id: taxiiCollection.id,
      input: { key: 'filters', value: jsonFilters },
    };
    commitMutation({
      mutation: taxiiCollectionMutationFieldPatch,
      variables,
      setSubmitting: undefined,
      onCompleted: undefined,
      onError: undefined,
      optimisticResponse: undefined,
      optimisticUpdater: undefined,
      updater: undefined,
    });
  }, [filters]);
  const onSubmit: FormikConfig<TaxiiCollectionCreationForm>['onSubmit'] = () => {};

  const availableFilterKeys = useAvailableFilterKeysForEntityTypes(['Stix-Core-Object', 'stix-core-relationship']);
  return (
    <Formik
      onSubmit={onSubmit}
      enableReinitialize={true}
      initialValues={initialValues}
      validationSchema={taxiiCollectionValidation(t_i18n('This field is required'))}
    >
      {() => (
        <Form style={{ margin: '20px 0 20px 0' }}>
          <Field
            component={TextField}
            variant="standard"
            name="name"
            label={t_i18n('Name')}
            fullWidth={true}
            onSubmit={handleSubmitField}
          />
          <Field
            component={TextField}
            variant="standard"
            name="description"
            label={t_i18n('Description')}
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
              {t_i18n('Make this taxii collection public and available to anyone')}
            </AlertTitle>
            <FormControlLabel
              control={<Switch defaultChecked={!!initialValues.taxii_public}/>}
              style={{ marginLeft: 1 }}
              onChange={(_, checked) => handleSubmitField('taxii_public', checked.toString())}
              label={t_i18n('Public taxii collection')}
            />
            {!initialValues.taxii_public && (
              <ObjectMembersField
                label={'Accessible for'}
                style={fieldSpacingContainerStyle}
                onChange={handleSubmitFieldOptions}
                multiple={true}
                helpertext={t_i18n('Let the field empty to grant all authenticated users')}
                name="authorized_members"
              />
            )}
          </Alert>
          <Box sx={{ paddingTop: 4,
            display: 'flex',
            gap: 1 }}
          >
            <Filters
              availableFilterKeys={availableFilterKeys}
              helpers={helpers}
              searchContext={{ entityTypes: ['Stix-Core-Object', 'stix-core-relationship'] }}
            />
          </Box>
          <FilterIconButton
            filters={filters}
            helpers={helpers}
            styleNumber={2}
            redirection
            searchContext={{ entityTypes: ['Stix-Core-Object', 'stix-core-relationship'] }}
          />
        </Form>
      )}
    </Formik>
  );
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

export default TaxiiCollectionEditionFragment;
