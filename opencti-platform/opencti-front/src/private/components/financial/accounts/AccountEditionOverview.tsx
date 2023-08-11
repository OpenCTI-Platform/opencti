import { graphql, useFragment, useMutation } from 'react-relay';
import { FunctionComponent } from 'react';
import * as R from 'ramda';
import { Field, Form, Formik, FormikConfig } from 'formik';
import { AccountEditionOverview_financialAccount$key } from './__generated__/AccountEditionOverview_financialAccount.graphql';
import { useFormatter } from '../../../../components/i18n';
import { CurrencyCode, FinancialAccountStatus, FinancialAccountType, displayCurrencyCode, getAccountValidator } from './AccountCreation';
import TextField from '../../../../components/TextField';
import AutocompleteField from '../../../../components/AutocompleteField';
import { Option } from '../../common/form/ReferenceField';
import { convertCreatedBy, convertMarkings } from '../../../../utils/edition';
import useGranted, { KNOWLEDGE_KNUPDATE } from '../../../../utils/hooks/useGranted';
import useFormEditor from '../../../../utils/hooks/useFormEditor';
import CreatedByField from '../../common/form/CreatedByField';
import ObjectMarkingField from '../../common/form/ObjectMarkingField';
import { valToKey } from '../../../../utils/Localization';

export const accountEditionOverviewUpdate = graphql`
  mutation AccountEditionOverviewUpdateMutation(
    $id: ID!,
    $input: [EditInput]!
  ) {
    financialAccountFieldPatch(id: $id, input: $input) {
      ...AccountEditionOverview_financialAccount
    }
  }
`;

export const accountMutationFieldPatch = graphql`
  mutation AccountEditionOverviewFieldPatchMutation(
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

export const accountEditionOverviewFocus = graphql`
  mutation AccountEditionOverviewFocusMutation($id: ID!, $input: EditContext!) {
    financialAccountContextPatch(id: $id, input: $input) {
      id
    }
  }
`;

const accountMutationRelationAdd = graphql`
  mutation AccountEditionOverviewRelationAddMutation(
    $id: ID!
    $input: StixRefRelationshipAddInput!
  ) {
    financialAccountRelationAdd(id: $id, input: $input) {
      from {
        ...AccountEditionOverview_financialAccount
      }
    }
  }
`;

const accountMutationRelationDelete = graphql`
  mutation AccountEditionOverviewRelationDeleteMutation(
    $id: ID!
    $toId: StixRef!
    $relationship_type: String!
  ) {
    financialAccountRelationDelete(id: $id, toId: $toId, relationship_type: $relationship_type) {
      ...AccountEditionOverview_financialAccount
    }
  }
`;

const accountEditionOverviewFragment = graphql`
  fragment AccountEditionOverview_financialAccount on FinancialAccount {
    id
    currency_code
    name
    financial_account_number
    financial_account_status
    financial_account_type
    international_bank_account_number
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

interface AccountEditionOverviewProps {
  accountRef: AccountEditionOverview_financialAccount$key
}

interface AccountEditionFormValues {
  name: string
  financial_account_number: string
  international_bank_account_number: string
  currency_code: string // Drop-down value
  financial_account_status: string // Drop-down value
  financial_account_type: string // Drop-down value
  createdBy?: Option
  objectMarking?: Option[]
}

const AccountEditionOverviewComponent: FunctionComponent<AccountEditionOverviewProps> = ({ accountRef }) => {
  const { t } = useFormatter();
  const userIsKnowledgeEditor = useGranted([KNOWLEDGE_KNUPDATE]);
  const account = useFragment(accountEditionOverviewFragment, accountRef);
  const accountValidator = getAccountValidator(t);
  const [commitUpdate] = useMutation(accountEditionOverviewUpdate);

  const onSubmit: FormikConfig<AccountEditionFormValues>['onSubmit'] = (values: AccountEditionFormValues, { setSubmitting }) => {
    const finalValues = R.pipe(
      R.dissoc('createdBy'),
      R.dissoc('objectMarking'),
    )(values);
    commitUpdate({
      variables: {
        id: account.id,
        input: finalValues,
      },
      onCompleted: () => setSubmitting(false),
    });
  };

  const queries = {
    fieldPatch: accountMutationFieldPatch,
    relationAdd: accountMutationRelationAdd,
    relationDelete: accountMutationRelationDelete,
    editionFocus: accountEditionOverviewFocus,
  };
  const editor = useFormEditor(account, false, queries, accountValidator);

  const handleSubmitField = (name: string, value: string) => {
    accountValidator
      .validateAt(name, { [name]: value })
      .then(() => {
        commitUpdate({
          variables: {
            id: account.id,
            input: [{
              key: name,
              value,
            }]
          }
        })
      })
      .catch(() => false);
  };

  const createdBy = convertCreatedBy(account);
  const objectMarking = convertMarkings(account);
  const initialValues = R.pipe(
    R.assoc('createdBy', createdBy),
    R.assoc('objectMarking', objectMarking),
    R.pick([
      'currency_code',
      'name',
      'financial_account_number',
      'financial_account_status',
      'financial_account_type',
      'international_bank_account_number',
      'createdBy',
      'objectMarking',
    ]),
  )(account);

  return (
    <Formik
      enableReinitalize={true}
      initialValues={initialValues as never}
      validationSchema={accountValidator}
      onSubmit={() => {}}
    >
      {({ submitForm, setFieldValue }) => (
        <Form style={{ margin: '20px 0 20px 0' }}>
          <Field
            component={TextField}
            variant="standard"
            name="name"
            label={t('Account Name')}
            fullWidth={true}
            onSubmit={(name: string, value: string) => handleSubmitField(name, value)}
          />
          <div style={{ height: '20px' }}></div>
          <Field
            component={TextField}
            variant="standard"
            name="financial_account_number"
            label={t('Account Number')}
            fullWidth={true}
            onSubmit={(name: string, value: string) => handleSubmitField(name, value)}
          />
          <div style={{ height: '20px' }}></div>
          <Field
            component={TextField}
            variant="standard"
            name="international_bank_account_number"
            label={t('International Bank Account Number')}
            fullWidth={true}
            onSubmit={(name: string, value: string) => handleSubmitField(name, value)}
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
            value={displayCurrencyCode(account?.currency_code || t('Unknown'))}
            renderOption={(props: React.HTMLAttributes<HTMLLIElement>, option: string) => (
              <li {...props}> {displayCurrencyCode(option)} </li>
            )}
            onChange={(field: string, value: string) => {
              setFieldValue(field, value);
              handleSubmitField(field, value);
            }}
          />
          <Field
            component={AutocompleteField}
            name={'financial_account_status'}
            multiple={false}
            style={{ margin: '20px 0 0 0' }}
            textfieldprops={{
              variant: 'standard',
              label: t('Account Status'),
            }}
            noOptionsText={t('No available options')}
            options={Object.entries(FinancialAccountStatus)}
            value={t(valToKey(account?.financial_account_status, FinancialAccountStatus))}
            renderOption={(props: React.HTMLAttributes<HTMLLIElement>, [_, value]: [string, string]) => (
              <li {...props}> {t(value)} </li>
            )}
            onChange={(field: string, [key]: [string]) => {
              setFieldValue(field, key);
              handleSubmitField(field, key);
            }}
          />
          <Field
            component={AutocompleteField}
            name={'financial_account_type'}
            multiple={false}
            style={{ margin: '20px 0 0 0' }}
            textfieldprops={{
              variant: 'standard',
              label: t('Account Type'),
            }}
            noOptionsText={t('No available options')}
            options={Object.entries(FinancialAccountType)}
            value={t(valToKey(account?.financial_account_type, FinancialAccountType))}
            renderOption={(props: React.HTMLAttributes<HTMLLIElement>, [_, value]: [string, string]) => (
              <li {...props}> {t(value)} </li>
            )}
            onChange={(field: string, [key]: [string]) => {
              setFieldValue(field, key);
              handleSubmitField(field, key);
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

export default AccountEditionOverviewComponent;
