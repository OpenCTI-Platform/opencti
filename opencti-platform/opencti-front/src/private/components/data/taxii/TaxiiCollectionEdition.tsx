import React, { FunctionComponent, useEffect } from 'react';
import { createFragmentContainer, graphql } from 'react-relay';
import { Field, Form, Formik } from 'formik';
import * as Yup from 'yup';
import Alert from '@mui/material/Alert';
import AlertTitle from '@mui/material/AlertTitle';
import FormControlLabel from '@mui/material/FormControlLabel';
import Switch from '@mui/material/Switch';
import Box from '@mui/material/Box';
import { TaxiiCollectionEdition_taxiiCollection$data } from '@components/data/taxii/__generated__/TaxiiCollectionEdition_taxiiCollection.graphql';
import { FormikConfig } from 'formik/dist/types';
import ObjectMembersField from '../../common/form/ObjectMembersField';
import { useFormatter } from '../../../../components/i18n';
import { commitMutation } from '../../../../relay/environment';
import TextField from '../../../../components/TextField';
import Filters from '../../common/lists/Filters';
import { deserializeFilterGroupForFrontend, serializeFilterGroupForBackend, useAvailableFilterKeysForEntityTypes } from '../../../../utils/filters/filtersUtils';
import FilterIconButton from '../../../../components/FilterIconButton';
import { FieldOption, fieldSpacingContainerStyle } from '../../../../utils/field';
import { convertAuthorizedMembers, convertUser } from '../../../../utils/edition';
import useFiltersState from '../../../../utils/filters/useFiltersState';
import useGranted, { SETTINGS_SETACCESSES } from '../../../../utils/hooks/useGranted';
import { useTheme } from '@mui/material/styles';
import CreatorField from '../../common/form/CreatorField';

interface TaxiiCollectionCreationForm {
  restricted_members: FieldOption[] | null;
  taxii_public?: boolean | null;
  name: string | null;
  description: string | null;
  taxii_public_user_id?: FieldOption | string | null;
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
  restricted_members: Yup.array().nullable(),
  taxii_public: Yup.bool().nullable(),
  taxii_public_user_id: Yup.mixed().nullable(),
  include_inferences: Yup.bool().nullable(),
  score_to_confidence: Yup.bool().nullable(),
});

const TaxiiCollectionEditionContainer: FunctionComponent<{ taxiiCollection: TaxiiCollectionEdition_taxiiCollection$data }> = ({ taxiiCollection }) => {
  const { t_i18n } = useFormatter();
  const theme = useTheme();
  const isGrantedToSetAccesses = useGranted([SETTINGS_SETACCESSES]);
  const initialValues = {
    name: taxiiCollection.name ?? '',
    description: taxiiCollection.description ?? '',
    taxii_public: taxiiCollection.taxii_public,
    restricted_members: convertAuthorizedMembers(taxiiCollection),
    include_inferences: taxiiCollection.include_inferences,
    score_to_confidence: taxiiCollection.score_to_confidence,
    taxii_public_user_id: convertUser(taxiiCollection, 'taxii_public_user'),
  };
  const [filters, helpers] = useFiltersState(deserializeFilterGroupForFrontend(taxiiCollection.filters) ?? undefined);
  const handleSubmitField = (name: string, value: FieldOption[] | string) => {
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

  const handleSubmitFieldOptions = (name: string, value: FieldOption[]) => taxiiCollectionValidation(t_i18n('This field is required'))
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
    <Formik<TaxiiCollectionCreationForm>
      onSubmit={onSubmit}
      enableReinitialize={true}
      initialValues={initialValues}
      validationSchema={taxiiCollectionValidation(t_i18n('This field is required'))}
    >
      {({ values, setFieldValue }) => (
        <Form>
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
            sx={{
              width: '100%',
              marginTop: 20,
              '& .MuiAlert-message': {
                width: '100%',
                overflow: 'hidden',
              },
            }}
            severity="warning"
            variant="outlined"
            style={{ position: 'relative' }}
          >
            <AlertTitle>
              {t_i18n('Make this TAXII collection public and available to anyone')}
            </AlertTitle>
            <FormControlLabel
              control={<Switch checked={!!values.taxii_public} disabled={!isGrantedToSetAccesses} />}
              style={{ marginLeft: 1 }}
              onChange={(_, checked) => {
                setFieldValue('taxii_public', checked);
                if (!checked) {
                  handleSubmitField('taxii_public', 'false');
                }
              }}
              label={t_i18n('Public collection')}
            />
            {!values.taxii_public && (
              <ObjectMembersField
                label="Accessible for"
                style={fieldSpacingContainerStyle}
                onChange={handleSubmitFieldOptions}
                multiple={true}
                helpertext={t_i18n('Leave the field empty to grant all authenticated users')}
                name="restricted_members"
              />
            )}
            {values.taxii_public && (
              <CreatorField
                name="taxii_public_user_id"
                label={t_i18n('Share data corresponding to permissions associated with this user')}
                containerStyle={fieldSpacingContainerStyle}
                disabled={!isGrantedToSetAccesses}
                onChange={(_, value) => {
                  const userId = (value as FieldOption)?.value ?? '';
                  if (!taxiiCollection.taxii_public) {
                    commitMutation({
                      mutation: taxiiCollectionMutationFieldPatch,
                      variables: {
                        id: taxiiCollection.id,
                        input: [
                          { key: 'taxii_public_user_id', value: userId },
                          { key: 'taxii_public', value: 'true' },
                        ],
                      },
                      setSubmitting: undefined,
                      onCompleted: undefined,
                      onError: undefined,
                      optimisticResponse: undefined,
                      optimisticUpdater: undefined,
                      updater: undefined,
                    });
                  } else {
                    handleSubmitField('taxii_public_user_id', userId);
                  }
                }}
              />
            )}
          </Alert>
          <Box sx={{ display: 'flex', alignItems: 'center', marginTop: '20px' }}>
            <FormControlLabel
              control={<Switch defaultChecked={!!initialValues.include_inferences} />}
              style={{ marginLeft: 1 }}
              onChange={(_, checked) => handleSubmitField('include_inferences', checked.toString())}
              label={t_i18n('Include inferences')}
            />
          </Box>
          <Box sx={{ display: 'flex', alignItems: 'center', marginTop: '20px' }}>
            <FormControlLabel
              control={<Switch defaultChecked={!!initialValues.score_to_confidence} />}
              style={{ marginLeft: 1 }}
              onChange={(_, checked) => handleSubmitField('score_to_confidence', checked.toString())}
              label={t_i18n('Copy OpenCTI scores to confidence level for indicators')}
            />
          </Box>
          <Box sx={{
            paddingTop: 4,
            display: 'flex',
            alignItems: 'center',
            gap: theme.spacing(1),
            marginBottom: theme.spacing(1),
          }}
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
        taxii_public_user {
          id
          entity_type
          name
        }
        include_inferences
        score_to_confidence
        authorized_members {
          id
          member_id
          name
        }
      }
    `,
  },
);

export default TaxiiCollectionEditionFragment;
