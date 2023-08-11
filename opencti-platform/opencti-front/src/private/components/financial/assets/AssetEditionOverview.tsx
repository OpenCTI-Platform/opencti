import { graphql, useFragment, useMutation } from 'react-relay';
import { FunctionComponent } from 'react';
import * as R from 'ramda';
import { Field, Form, Formik, FormikConfig } from 'formik';
import { AssetEditionOverview_financialAsset$key } from './__generated__/AssetEditionOverview_financialAsset.graphql';
import { useFormatter } from '../../../../components/i18n';
import { CurrencyCode, displayCurrencyCode } from '../accounts/AccountCreation';
import { FinancialAssetType, assetShape } from './AssetCreation';
import { Option } from '../../common/form/ReferenceField';
import TextField from '../../../../components/TextField';
import AutocompleteField from '../../../../components/AutocompleteField';
import CreatedByField from '../../common/form/CreatedByField';
import ObjectMarkingField from '../../common/form/ObjectMarkingField';
import { convertCreatedBy, convertMarkings } from '../../../../utils/edition';
import useFormEditor from '../../../../utils/hooks/useFormEditor';
import useGranted, { KNOWLEDGE_KNUPDATE } from '../../../../utils/hooks/useGranted';
import { useSchemaCreationValidation } from '../../../../utils/hooks/useEntitySettings';
import { valToKey } from '../../../../utils/Localization';

export const assetEditionOverviewUpdate = graphql`
  mutation AssetEditionOverviewUpdateMutation(
    $input: FinancialAssetUpdateInput!
  ) {
    financialAssetUpdate(input: $input) {
      ...AssetEditionOverview_financialAsset
    }
  }
`;

export const assetMutationFieldPatch = graphql`
  mutation AssetEditionOverviewFieldPatchMutation(
    $id: ID!
    $input: [EditInput]!
  ) {
    stixDomainObjectEdit(id: $id) {
      fieldPatch(input: $input) {
        createdBy {
          ... on Identity {
            id
            name
            entity_type
          }
        }
        objectMarking {
          edges {
            node {
              id
              definition_type
              definition
              x_opencti_order
              x_opencti_color
            }
          }
        }
        objectLabel {
          edges {
            node {
              id
              value
              color
            }
          }
        }
      }
    }
  }
`;

export const assetEditionOverviewFocus = graphql`
  mutation AssetEditionOverviewFocusMutation($id: ID!, $input: EditContext!) {
    financialAssetContextPatch(id: $id, input: $input) {
      id
    }
  }
`;

const assetMutationRelationAdd = graphql`
  mutation AssetEditionOverviewRelationAddMutation(
    $id: ID!
    $input: StixRefRelationshipAddInput!
  ) {
    financialAssetRelationAdd(id: $id, input: $input) {
      from {
        ...AssetEditionOverview_financialAsset
      }
    }
  }
`;

const assetMutationRelationDelete = graphql`
  mutation AssetEditionOverviewRelationDeleteMutation(
    $id: ID!
    $toId: StixRef!
    $relationship_type: String!
  ) {
    financialAssetRelationDelete(id: $id, toId: $toId, relationship_type: $relationship_type) {
      ...AssetEditionOverview_financialAsset
    }
  }
`;

const assetEditionOverviewFragment = graphql`
  fragment AssetEditionOverview_financialAsset on FinancialAsset {
    id
    name
    asset_type
    asset_value
    currency_code
    createdBy {
      ... on Identity {
        id
        name
        entity_type
      }
    }
    objectMarking {
      edges {
        node {
          id
          definition_type
          definition
          x_opencti_order
          x_opencti_color
        }
      }
    }
    status {
      id
      order
      template {
        name
        color
      }
    }
    workflowEnabled
  }
`;

interface AssetEditionOverviewProps {
  assetRef: AssetEditionOverview_financialAsset$key
}

interface AssetEditionFormValues {
  name: string
  asset_type: string
  asset_value: string
  currency_code: string
  createdBy?: Option
  objectMarking?: Option[]
}

const AssetEditionOverviewComponent: FunctionComponent<AssetEditionOverviewProps> = ({ assetRef }) => {
  const { t } = useFormatter();
  const userIsKnowledgeEditor = useGranted([KNOWLEDGE_KNUPDATE]);
  const asset = useFragment(assetEditionOverviewFragment, assetRef);
  const assetValidator = useSchemaCreationValidation('Financial-Asset', assetShape(t));
  const [commitUpdate] = useMutation(assetEditionOverviewUpdate);

  const onSubmit: FormikConfig<AssetEditionFormValues>['onSubmit'] = (values: AssetEditionFormValues, { setSubmitting }) => {
    const finalValues = R.pipe(
      R.dissoc('createdBy'),
      R.dissoc('objectMarking'),
      R.assoc('id', asset.id),
      R.assoc('asset_value', Number(values.asset_value)),
    )(values);
    commitUpdate({
      variables: {
        input: finalValues,
      },
      onCompleted: () => setSubmitting(false),
    });
  };

  const queries = {
    fieldPatch: assetMutationFieldPatch,
    relationAdd: assetMutationRelationAdd,
    relationDelete: assetMutationRelationDelete,
    editionFocus: assetEditionOverviewFocus,
  };
  const editor = useFormEditor(asset, false, queries, assetValidator);

  const handleSubmitField = (
    name: string,
    value: string | string[],
    submitForm: (() => Promise<void>),
  ) => {
    assetValidator
      .validateAt(name, { [name]: value })
      .then(async () => {
        const oldValue = String(R.prop(name, asset));
        if (value !== oldValue) {
          await submitForm();
        }
      })
      .catch(() => { });
  };

  const createdBy = convertCreatedBy(asset);
  const objectMarking = convertMarkings(asset);
  const initialValues = R.pipe(
    R.assoc('createdBy', createdBy),
    R.assoc('objectMarking', objectMarking),
    R.pick([
      'name',
      'asset_type',
      'asset_value',
      'currency_code',
      'createdBy',
      'objectMarking',
    ]),
  )(asset);

  return (
    <Formik
      enableReinitalize={true}
      initialValues={initialValues as never}
      validationSchema={assetValidator}
      onSubmit={onSubmit}
    >
      {({ submitForm, setFieldValue }) => (
        <Form style={{ margin: '20px 0 20px 0' }}>
          <Field
            component={TextField}
            variant="standard"
            name="name"
            label={t('Asset Name')}
            fullWidth={true}
            onSubmit={(name: string, value: string) => handleSubmitField(name, value, submitForm)}
          />
          <Field
            component={AutocompleteField}
            name={'asset_type'}
            multiple={false}
            style={{ margin: '20px 0 0 0' }}
            textfieldprops={{
              variant: 'standard',
              label: t('Asset Type'),
            }}
            noOptionsText={t('No available options')}
            options={Object.entries(FinancialAssetType)}
            value={t(valToKey(asset?.asset_type, FinancialAssetType))}
            renderOption={(props: React.HTMLAttributes<HTMLLIElement>, [_, value]: [string, string]) => (
              <li {...props}> {t(value)} </li>
            )}
            onChange={(field: string, [key]: [string]) => {
              setFieldValue(field, key);
              submitForm();
            }}
          />
          <div style={{ height: '20px' }}></div>
          <Field
            component={TextField}
            variant="standard"
            name="asset_value"
            label={t('Asset Value')}
            fullWidth={true}
            onSubmit={(name: string, value: string) => handleSubmitField(name, value, submitForm)}
          />
          <Field
            component={AutocompleteField}
            name={'currency_code'}
            multiple={false}
            style={{ margin: '20px 0 0 0' }}
            textfieldprops={{
              variant: 'standard',
              label: t('Currency Code'),
            }}
            noOptionsText={t('No available options')}
            options={Object.values(CurrencyCode)}
            value={displayCurrencyCode(asset?.currency_code || t('Unknown'))}
            renderOption={(props: React.HTMLAttributes<HTMLLIElement>, option: string) => (
              <li {...props}> {displayCurrencyCode(option)} </li>
            )}
            onChange={(field: string, value: string) => {
              setFieldValue(field, value);
              submitForm();
            }}
          />
          {userIsKnowledgeEditor && (
            <CreatedByField
              name="createdBy"
              style={{ marginTop: 30, width: '100%' }}
              setFieldValue={setFieldValue}
              onChange={editor.changeCreated}
            />
          )}
          <ObjectMarkingField
            name="objectMarking"
            style={{ marginTop: userIsKnowledgeEditor ? 20 : 30, width: '100%' }}
            onChange={editor.changeMarking}
          />
        </Form>
      )}
    </Formik>
  );
};

export default AssetEditionOverviewComponent;
