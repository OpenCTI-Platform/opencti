import React from 'react';
import { createFragmentContainer, graphql } from 'react-relay';
import { Field, Form, Formik } from 'formik';
import { assoc, difference, filter, fromPairs, head, includes, map, pathOr, pick, pipe } from 'ramda';
import { useHistory } from 'react-router-dom';
import TextField from '../../../../components/TextField';
import { SubscriptionFocus } from '../../../../components/Subscription';
import { commitMutation, QueryRenderer } from '../../../../relay/environment';
import CreatedByField from '../../common/form/CreatedByField';
import ObjectMarkingField from '../../common/form/ObjectMarkingField';
import { stixCyberObservablesLinesAttributesQuery } from './StixCyberObservablesLines';
import { buildDate } from '../../../../utils/Time';
import SwitchField from '../../../../components/SwitchField';
import MarkDownField from '../../../../components/MarkDownField';
import DateTimePickerField from '../../../../components/DateTimePickerField';
import {
  booleanAttributes,
  dateAttributes,
  ignoredAttributes,
  multipleAttributes,
  numberAttributes,
} from '../../../../utils/Entity';
import { fieldSpacingContainerStyle } from '../../../../utils/field';
import ArtifactField from '../../common/form/ArtifactField';
import OpenVocabField from '../../common/form/OpenVocabField';
import { useFormatter } from '../../../../components/i18n';
import useVocabularyCategory from '../../../../utils/hooks/useVocabularyCategory';

const stixCyberObservableMutationFieldPatch = graphql`
  mutation StixCyberObservableEditionOverviewFieldPatchMutation(
    $id: ID!
    $input: [EditInput]!
  ) {
    stixCyberObservableEdit(id: $id) {
      fieldPatch(input: $input) {
        id
        ...StixCyberObservableEditionOverview_stixCyberObservable
        ...StixCyberObservable_stixCyberObservable
      }
    }
  }
`;

export const stixCyberObservableEditionOverviewFocus = graphql`
  mutation StixCyberObservableEditionOverviewFocusMutation(
    $id: ID!
    $input: EditContext!
  ) {
    stixCyberObservableEdit(id: $id) {
      contextPatch(input: $input) {
        id
      }
    }
  }
`;

const stixCyberObservableMutationRelationAdd = graphql`
  mutation StixCyberObservableEditionOverviewRelationAddMutation(
    $id: ID!
    $input: StixMetaRelationshipAddInput
  ) {
    stixCyberObservableEdit(id: $id) {
      relationAdd(input: $input) {
        from {
          ...StixCyberObservableEditionOverview_stixCyberObservable
        }
      }
    }
  }
`;

const stixCyberObservableMutationRelationDelete = graphql`
  mutation StixCyberObservableEditionOverviewRelationDeleteMutation(
    $id: ID!
    $toId: StixRef!
    $relationship_type: String!
  ) {
    stixCyberObservableEdit(id: $id) {
      relationDelete(toId: $toId, relationship_type: $relationship_type) {
        ...StixCyberObservableEditionOverview_stixCyberObservable
        ...StixCyberObservable_stixCyberObservable
      }
    }
  }
`;

const StixCyberObservableEditionOverviewComponent = ({ stixCyberObservable, enableReferences, context }) => {
  const history = useHistory();
  const { t } = useFormatter();
  const { isVocabularyField, fieldToCategory } = useVocabularyCategory();

  const handleChangeFocus = (name) => {
    commitMutation({
      mutation: stixCyberObservableEditionOverviewFocus,
      variables: {
        id: stixCyberObservable.id,
        input: {
          focusOn: name,
        },
      },
    });
  };

  const handleSubmitField = (name, value) => {
    let finalName = name;
    let finalValue = value || '';
    if (name.includes('hashes')) {
      finalName = name.replace('hashes_', 'hashes.');
    }
    if (multipleAttributes.includes(finalName)) {
      if (finalValue.length > 0) {
        finalValue = finalValue.split(',');
      } else {
        finalValue = [];
      }
    }
    commitMutation({
      mutation: stixCyberObservableMutationFieldPatch,
      variables: {
        id: stixCyberObservable.id,
        input: { key: finalName, value: finalValue },
      },
      onCompleted: (response) => {
        if (
          response.stixCyberObservableEdit.fieldPatch.id
          !== stixCyberObservable.id
        ) {
          history.push(
            `/dashboard/observations/observables/${response.stixCyberObservableEdit.fieldPatch.id}`,
          );
        }
      },
    });
  };

  const handleChangeCreatedBy = (name, value) => {
    if (!enableReferences) {
      commitMutation({
        mutation: stixCyberObservableMutationFieldPatch,
        variables: {
          id: stixCyberObservable.id,
          input: { key: 'createdBy', value: value.value || '' },
        },
      });
    }
  };

  const handleChangeRef = (name, value) => {
    if (!enableReferences) {
      commitMutation({
        mutation: stixCyberObservableMutationFieldPatch,
        variables: {
          id: stixCyberObservable.id,
          input: { key: name, value: value.value || '' },
        },
      });
    }
  };

  const handleChangeObjectMarking = (name, values) => {
    const currentMarkingDefinitions = pipe(
      pathOr([], ['objectMarking', 'edges']),
      map((n) => ({
        label: n.node.definition,
        value: n.node.id,
      })),
    )(stixCyberObservable);
    const added = difference(values, currentMarkingDefinitions);
    const removed = difference(currentMarkingDefinitions, values);
    if (added.length > 0) {
      commitMutation({
        mutation: stixCyberObservableMutationRelationAdd,
        variables: {
          id: stixCyberObservable.id,
          input: {
            toId: head(added).value,
            relationship_type: 'object-marking',
          },
        },
      });
    }
    if (removed.length > 0) {
      commitMutation({
        mutation: stixCyberObservableMutationRelationDelete,
        variables: {
          id: stixCyberObservable.id,
          toId: head(removed).value,
          relationship_type: 'object-marking',
        },
      });
    }
  };

  return (
      <QueryRenderer
        query={stixCyberObservablesLinesAttributesQuery}
        variables={{ elementType: [stixCyberObservable.entity_type] }}
        render={({ props }) => {
          if (props && props.schemaAttributes) {
            const createdBy = pathOr(null, ['createdBy', 'name'], stixCyberObservable) === null
              ? ''
              : {
                label: pathOr(
                  null,
                  ['createdBy', 'name'],
                  stixCyberObservable,
                ),
                value: pathOr(
                  null,
                  ['createdBy', 'id'],
                  stixCyberObservable,
                ),
              };
            const objectMarking = pipe(
              pathOr([], ['objectMarking', 'edges']),
              map((n) => ({
                label: n.node.definition,
                value: n.node.id,
              })),
            )(stixCyberObservable);
            const initialValues = pipe(
              assoc('createdBy', createdBy),
              assoc('objectMarking', objectMarking),
              pick([
                'x_opencti_score',
                'x_opencti_description',
                'createdBy',
                'killChainPhases',
                'objectMarking',
              ]),
            )(stixCyberObservable);
            const attributes = pipe(
              map((n) => n.node),
              filter(
                (n) => !includes(n.value, ignoredAttributes)
                  && !n.value.startsWith('i_'),
              ),
            )(props.schemaAttributes.edges);
            for (const attribute of attributes) {
              if (includes(attribute.value, dateAttributes)) {
                initialValues[attribute.value] = stixCyberObservable[attribute.value]
                  ? buildDate(stixCyberObservable[attribute.value])
                  : null;
              } else if (includes(attribute.value, multipleAttributes)) {
                initialValues[attribute.value] = stixCyberObservable[attribute.value]
                  ? stixCyberObservable[attribute.value].join(',')
                  : null;
              } else if (attribute.value === 'hashes') {
                const hashes = pipe(
                  map((n) => [n.algorithm, n.hash]),
                  fromPairs,
                )(stixCyberObservable.hashes);
                initialValues.hashes_MD5 = hashes.MD5;
                initialValues['hashes_SHA-1'] = hashes['SHA-1'];
                initialValues['hashes_SHA-256'] = hashes['SHA-256'];
                initialValues['hashes_SHA-512'] = hashes['SGA-512'];
              } else {
                initialValues[attribute.value] = stixCyberObservable[attribute.value];
              }
            }
            return (
              <Formik
                enableReinitialize={true}
                initialValues={initialValues}
                onSubmit={() => true}
              >
                {({ setFieldValue }) => (
                  <Form style={{ margin: '20px 0 20px 0' }}>
                    <Field
                      component={TextField}
                      variant="standard"
                      name="x_opencti_score"
                      label={t('Score')}
                      fullWidth={true}
                      type="number"
                      onFocus={handleChangeFocus}
                      onSubmit={handleSubmitField}
                      helperText={
                        <SubscriptionFocus
                          context={context}
                          fieldName="x_opencti_score"
                        />
                      }
                    />
                    <Field
                      component={MarkDownField}
                      name="x_opencti_description"
                      label={t('Description')}
                      fullWidth={true}
                      multiline={true}
                      rows="4"
                      style={{ marginTop: 20 }}
                      onFocus={handleChangeFocus}
                      onSubmit={handleSubmitField}
                      helperText={
                        <SubscriptionFocus
                          context={context}
                          fieldName="x_opencti_description"
                        />
                      }
                    />
                    {attributes.map((attribute) => {
                      if (attribute.value === 'hashes') {
                        return (
                          <div key={attribute.value}>
                            <Field
                              component={TextField}
                              variant="standard"
                              name="hashes_MD5"
                              label={t('hash_md5')}
                              fullWidth={true}
                              style={{ marginTop: 20 }}
                              onFocus={handleChangeFocus}
                              onSubmit={handleSubmitField}
                              helperText={
                                <SubscriptionFocus
                                  context={context}
                                  fieldName="hashes_MD5"
                                />
                              }
                            />
                            <Field
                              component={TextField}
                              variant="standard"
                              name="hashes_SHA-1"
                              label={t('hash_sha-1')}
                              fullWidth={true}
                              style={{ marginTop: 20 }}
                              onFocus={handleChangeFocus}
                              onSubmit={handleSubmitField}
                              helperText={
                                <SubscriptionFocus
                                  context={context}
                                  fieldName="hashes_SHA-1"
                                />
                              }
                            />
                            <Field
                              component={TextField}
                              variant="standard"
                              name="hashes_SHA-256"
                              label={t('hash_sha-256')}
                              fullWidth={true}
                              style={{ marginTop: 20 }}
                              onFocus={handleChangeFocus}
                              onSubmit={handleSubmitField}
                              helperText={
                                <SubscriptionFocus
                                  context={context}
                                  fieldName="hashes_SHA-256"
                                />
                              }
                            />
                            <Field
                              component={TextField}
                              variant="standard"
                              name="hashes.SHA-512"
                              label={t('hash_sha-512')}
                              fullWidth={true}
                              style={{ marginTop: 20 }}
                              onFocus={handleChangeFocus}
                              onSubmit={handleSubmitField}
                              helperText={
                                <SubscriptionFocus
                                  context={context}
                                  fieldName="hashes_SHA-512"
                                />
                              }
                            />
                          </div>
                        );
                      }
                      if (includes(attribute.value, dateAttributes)) {
                        return (
                          <Field
                            component={DateTimePickerField}
                            key={attribute.value}
                            name={attribute.value}
                            withSeconds={true}
                            onFocus={handleChangeFocus}
                            onSubmit={handleSubmitField}
                            TextFieldProps={{
                              label: attribute.value,
                              variant: 'standard',
                              fullWidth: true,
                              style: { marginTop: 20 },
                              helperText: (
                                <SubscriptionFocus
                                  context={context}
                                  fieldName={attribute.value}
                                />
                              ),
                            }}
                          />
                        );
                      }
                      if (includes(attribute.value, numberAttributes)) {
                        return (
                          <Field
                            component={TextField}
                            variant="standard"
                            key={attribute.value}
                            name={attribute.value}
                            label={attribute.value}
                            fullWidth={true}
                            number={true}
                            style={{ marginTop: 20 }}
                            onFocus={handleChangeFocus}
                            onSubmit={handleSubmitField}
                            helperText={
                              <SubscriptionFocus
                                context={context}
                                fieldName={attribute.value}
                              />
                            }
                          />
                        );
                      }
                      if (includes(attribute.value, booleanAttributes)) {
                        return (
                          <Field
                            component={SwitchField}
                            type="checkbox"
                            key={attribute.value}
                            name={attribute.value}
                            label={attribute.value}
                            containerstyle={{ marginTop: 20 }}
                            onChange={handleSubmitField}
                          />
                        );
                      }
                      if (isVocabularyField(stixCyberObservable.entity_type, attribute.value)) {
                        return (
                          <OpenVocabField
                            key={attribute.value}
                            label={t(attribute.value)}
                            type={fieldToCategory(stixCyberObservable.entity_type, attribute.value)}
                            name={attribute.value}
                            variant={'edit'}
                            onChange={handleSubmitField}
                            containerStyle={fieldSpacingContainerStyle}
                            multiple={false}
                            editContext={context}
                          />
                        );
                      }
                      if (attribute.value === 'obsContent') {
                        const artifact = stixCyberObservable[attribute.value];
                        return (
                          <ArtifactField
                            key={attribute.value}
                            attributeName={attribute.value}
                            attributeValue={artifact ? {
                              label: artifact.observable_value ?? artifact.id,
                              value: artifact.id,
                            } : undefined}
                            onChange={handleChangeRef}
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
                          onFocus={handleChangeFocus}
                          onSubmit={handleSubmitField}
                          helperText={
                            <SubscriptionFocus
                              context={context}
                              fieldName={attribute.value}
                            />
                          }
                        />
                      );
                    })}
                    <CreatedByField
                      name="createdBy"
                      style={fieldSpacingContainerStyle}
                      setFieldValue={setFieldValue}
                      helpertext={
                        <SubscriptionFocus
                          context={context}
                          fieldName="createdBy"
                        />
                      }
                      onChange={handleChangeCreatedBy}
                    />
                    <ObjectMarkingField
                      name="objectMarking"
                      style={fieldSpacingContainerStyle}
                      helpertext={
                        <SubscriptionFocus
                          context={context}
                          fieldname="objectMarking"
                        />
                      }
                      onChange={handleChangeObjectMarking}
                    />
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

const StixCyberObservableEditionOverview = createFragmentContainer(
  StixCyberObservableEditionOverviewComponent,
  {
    stixCyberObservable: graphql`
      fragment StixCyberObservableEditionOverview_stixCyberObservable on StixCyberObservable {
        id
        entity_type
        ... on AutonomousSystem {
          number
          name
          rir
        }
        ... on Directory {
          path
          path_enc
          ctime
          mtime
          atime
        }
        ... on DomainName {
          value
        }
        ... on EmailAddr {
          value
          display_name
        }
        ... on EmailMessage {
          is_multipart
          attribute_date
          content_type
          message_id
          subject
          received_lines
          body
        }
        ... on Artifact {
          x_opencti_additional_names
          mime_type
          payload_bin
          url
          encryption_algorithm
          decryption_key
          hashes {
            algorithm
            hash
          }
        }
        ... on StixFile {
          extensions
          size
          name
          x_opencti_additional_names
          name_enc
          magic_number_hex
          mime_type
          ctime
          mtime
          atime
          obsContent{
            id
            ... on Artifact {
              observable_value
              url
            }
          }
          hashes {
            algorithm
            hash
          }
        }
        ... on X509Certificate {
          is_self_signed
          version
          serial_number
          signature_algorithm
          issuer
          subject
          subject_public_key_algorithm
          subject_public_key_modulus
          subject_public_key_exponent
          validity_not_before
          validity_not_after
          hashes {
            algorithm
            hash
          }
          basic_constraints
          name_constraints
          policy_constraints
          key_usage
          extended_key_usage
          subject_key_identifier
          authority_key_identifier
          subject_alternative_name
          issuer_alternative_name
          subject_directory_attributes
          crl_distribution_points
          inhibit_any_policy
          private_key_usage_period_not_before
          private_key_usage_period_not_after
          certificate_policies
          policy_mappings
        }
        ... on IPv4Addr {
          value
        }
        ... on IPv6Addr {
          value
        }
        ... on MacAddr {
          value
        }
        ... on Mutex {
          name
        }
        ... on NetworkTraffic {
          extensions
          start
          end
          is_active
          src_port
          dst_port
          protocols
          src_byte_count
          dst_byte_count
          src_packets
          dst_packets
        }
        ... on Process {
          extensions
          is_hidden
          pid
          created_time
          cwd
          command_line
          environment_variables
          ## windows-process-ext
          aslr_enabled
          dep_enabled
          priority
          owner_sid
          window_title
          integrity_level
          ## windows-service-ext
          service_name
          descriptions
          display_name
          group_name
          start_type
          service_type
          service_status
        }
        ... on Software {
          name
          cpe
          swid
          languages
          vendor
          version
        }
        ... on Url {
          value
        }
        ... on UserAccount {
          extensions
          user_id
          credential
          account_login
          account_type
          display_name
          is_service_account
          is_privileged
          can_escalate_privs
          is_disabled
          account_created
          account_expires
          credential_last_changed
          account_first_login
          account_last_login
        }
        ... on WindowsRegistryKey {
          attribute_key
          modified_time
          number_of_subkeys
        }
        ... on WindowsRegistryValueType {
          name
          data
          data_type
        }
        ... on Hostname {
          value
        }
        ... on CryptographicKey {
          value
        }
        ... on CryptocurrencyWallet {
          value
        }
        ... on Text {
          value
        }
        ... on UserAgent {
          value
        }
        ... on BankAccount {
          iban
          bic
          account_number
        }
        ... on PhoneNumber {
          value
        }
        ... on PaymentCard {
          card_number
          expiration_date
          cvv
          holder_name
        }
        ... on MediaContent {
          title
          content
          media_category
          url
          publication_date
        }
        x_opencti_score
        x_opencti_description
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
              definition
              definition_type
              x_opencti_order
              x_opencti_color
            }
          }
        }
      }
    `,
  },
);

export default StixCyberObservableEditionOverview;
