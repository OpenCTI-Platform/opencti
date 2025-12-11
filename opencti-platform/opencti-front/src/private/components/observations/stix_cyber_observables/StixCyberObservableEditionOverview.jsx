import React from 'react';
import { createFragmentContainer, graphql } from 'react-relay';
import { Field, Form, Formik } from 'formik';
import * as R from 'ramda';
import { assoc, difference, filter, fromPairs, head, includes, map, pick, pipe } from 'ramda';
import { useNavigate } from 'react-router-dom';
import * as Yup from 'yup';
import TextField from '../../../../components/TextField';
import { SubscriptionFocus } from '../../../../components/Subscription';
import { commitMutation, QueryRenderer } from '../../../../relay/environment';
import CreatedByField from '../../common/form/CreatedByField';
import ObjectMarkingField from '../../common/form/ObjectMarkingField';
import { stixCyberObservablesLinesAttributesQuery } from './StixCyberObservablesLines';
import { buildDate } from '../../../../utils/Time';
import SwitchField from '../../../../components/fields/SwitchField';
import MarkdownField from '../../../../components/fields/MarkdownField';
import DateTimePickerField from '../../../../components/DateTimePickerField';
import { fieldSpacingContainerStyle } from '../../../../utils/field';
import ArtifactField from '../../common/form/ArtifactField';
import OpenVocabField from '../../common/form/OpenVocabField';
import { useFormatter } from '../../../../components/i18n';
import useVocabularyCategory from '../../../../utils/hooks/useVocabularyCategory';
import { adaptFieldValue } from '../../../../utils/String';
import { convertMarkings } from '../../../../utils/edition';
import useAttributes from '../../../../utils/hooks/useAttributes';

const stixCyberObservableMutationFieldPatch = graphql`
  mutation StixCyberObservableEditionOverviewFieldPatchMutation(
    $id: ID!
    $input: [EditInput]!
    $commitMessage: String
    $references: [String]
  ) {
    stixCyberObservableEdit(id: $id) {
      fieldPatch(
        input: $input
        commitMessage: $commitMessage
        references: $references
      ) {
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
    $input: StixRefRelationshipAddInput!
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

const StixCyberObservableEditionOverviewComponent = ({
  stixCyberObservable,
  enableReferences,
  context,
  handleClose,
}) => {
  const navigate = useNavigate();
  const { t_i18n } = useFormatter();
  const { isVocabularyField, fieldToCategory } = useVocabularyCategory();
  const { booleanAttributes, dateAttributes, ignoredAttributes, multipleAttributes, numberAttributes } = useAttributes();
  const onSubmit = (values, { setSubmitting }) => {
    const commitMessage = values.message;
    const references = R.pluck('value', values.references || []);
    const inputValues = R.pipe(
      R.dissoc('message'),
      R.dissoc('references'),
      R.assoc('x_opencti_workflow_id', values.x_opencti_workflow_id?.value),
      R.assoc('createdBy', values.createdBy?.value),
      R.assoc('objectMarking', R.pluck('value', values.objectMarking)),
      R.toPairs,
      R.map((n) => ({
        key: n[0],
        value: adaptFieldValue(n[1]),
      })),
    )(values);
    commitMutation({
      mutation: stixCyberObservableMutationFieldPatch,
      variables: {
        id: stixCyberObservable.id,
        input: inputValues,
        commitMessage:
          commitMessage && commitMessage.length > 0 ? commitMessage : null,
        references,
      },
      setSubmitting,
      onCompleted: () => {
        setSubmitting(false);
        handleClose();
      },
    });
  };
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
    if (!enableReferences) {
      let finalName = name;
      let finalValue = value || '';
      let object_path = null;
      if (name.includes('hashes')) {
        finalName = 'hashes';
        object_path = name;
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
          input: { key: finalName, object_path, value: finalValue },
        },
        onCompleted: (response) => {
          if (
            response.stixCyberObservableEdit.fieldPatch.id
            !== stixCyberObservable.id
          ) {
            navigate(
              `/dashboard/observations/observables/${response.stixCyberObservableEdit.fieldPatch.id}`,
            );
          }
        },
      });
    }
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
  const handleChangeObjectMarking = (name, values, operation) => {
    if (!enableReferences) {
      const currentMarkingDefinitions = convertMarkings(stixCyberObservable);
      const added = difference(values, currentMarkingDefinitions);
      const removed = difference(currentMarkingDefinitions, values);
      if (added.length > 0 && operation !== 'replace') {
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
      if (operation === 'replace') {
        commitMutation({
          mutation: stixCyberObservableMutationFieldPatch,
          variables: {
            id: stixCyberObservable.id,
            input: [{ key: name, value: values.map((m) => m.value), operation }],
          },
        });
      } else if (removed.length > 0) {
        commitMutation({
          mutation: stixCyberObservableMutationRelationDelete,
          variables: {
            id: stixCyberObservable.id,
            toId: head(removed).value,
            relationship_type: 'object-marking',
          },
        });
      }
    }
  };

  const stixCyberObservableValidation = Yup.object().shape({
    x_opencti_score: Yup.number().integer(t_i18n('The value must be an integer'))
      .nullable()
      .min(0, t_i18n('The value must be greater than or equal to 0'))
      .max(100, t_i18n('The value must be less than or equal to 100')),
  });

  return (
    <QueryRenderer
      query={stixCyberObservablesLinesAttributesQuery}
      variables={{ elementType: [stixCyberObservable.entity_type] }}
      render={({ props }) => {
        if (props && props.schemaAttributeNames) {
          const createdBy = (stixCyberObservable?.createdBy?.name ?? null) === null
            ? ''
            : {
              label: stixCyberObservable?.createdBy?.name ?? null,
              value: stixCyberObservable?.createdBy?.id ?? null,
            };
          const objectMarking = convertMarkings(stixCyberObservable);
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
          )(props.schemaAttributeNames.edges);
          for (const attribute of attributes) {
            if (includes(attribute.value, dateAttributes)) {
              initialValues[attribute.value] = stixCyberObservable[
                attribute.value
              ]
                ? buildDate(stixCyberObservable[attribute.value])
                : null;
            } else if (includes(attribute.value, multipleAttributes)) {
              initialValues[attribute.value] = stixCyberObservable[
                attribute.value
              ]
                ? stixCyberObservable[attribute.value].join(',')
                : null;
            } else if (attribute.value === 'hashes') {
              const hashes = pipe(
                map((n) => [n.algorithm, n.hash]),
                fromPairs,
              )(stixCyberObservable.hashes);
              initialValues['/hashes/MD5'] = hashes.MD5;
              initialValues['/hashes/SHA-1'] = hashes['SHA-1'];
              initialValues['/hashes/SHA-256'] = hashes['SHA-256'];
              initialValues['/hashes/SHA-512'] = hashes['SHA-512'];
            } else {
              initialValues[attribute.value] = stixCyberObservable[attribute.value];
            }
          }
          return (
            <Formik
              enableReinitialize={true}
              initialValues={initialValues}
              validationSchema={stixCyberObservableValidation}
              onSubmit={onSubmit}
            >
              {({ setFieldValue }) => (
                <Form>
                  <Field
                    component={TextField}
                    variant="standard"
                    name="x_opencti_score"
                    label={t_i18n('Score')}
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
                    component={MarkdownField}
                    name="x_opencti_description"
                    label={t_i18n('Description')}
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
                            name="/hashes/MD5"
                            label={t_i18n('hash_md5')}
                            fullWidth={true}
                            style={{ marginTop: 20 }}
                            onFocus={handleChangeFocus}
                            onSubmit={handleSubmitField}
                            helperText={
                              <SubscriptionFocus
                                context={context}
                                fieldName="/hashes/MD5"
                              />
                            }
                          />
                          <Field
                            component={TextField}
                            variant="standard"
                            name="/hashes/SHA-1"
                            label={t_i18n('hash_sha-1')}
                            fullWidth={true}
                            style={{ marginTop: 20 }}
                            onFocus={handleChangeFocus}
                            onSubmit={handleSubmitField}
                            helperText={
                              <SubscriptionFocus
                                context={context}
                                fieldName="/hashes/SHA-1"
                              />
                            }
                          />
                          <Field
                            component={TextField}
                            variant="standard"
                            name="/hashes/SHA-256"
                            label={t_i18n('hash_sha-256')}
                            fullWidth={true}
                            style={{ marginTop: 20 }}
                            onFocus={handleChangeFocus}
                            onSubmit={handleSubmitField}
                            helperText={
                              <SubscriptionFocus
                                context={context}
                                fieldName="/hashes/SHA-256"
                              />
                            }
                          />
                          <Field
                            component={TextField}
                            variant="standard"
                            name="/hashes/SHA-512"
                            label={t_i18n('hash_sha-512')}
                            fullWidth={true}
                            style={{ marginTop: 20 }}
                            onFocus={handleChangeFocus}
                            onSubmit={handleSubmitField}
                            helperText={
                              <SubscriptionFocus
                                context={context}
                                fieldName="/hashes/SHA-512"
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
                          textFieldProps={{
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
                    if (
                      isVocabularyField(
                        stixCyberObservable.entity_type,
                        attribute.value,
                      )
                    ) {
                      return (
                        <OpenVocabField
                          key={attribute.value}
                          label={t_i18n(attribute.value)}
                          type={fieldToCategory(
                            stixCyberObservable.entity_type,
                            attribute.value,
                          )}
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
                          attributeValue={
                            artifact
                              ? {
                                label:
                                  artifact.observable_value ?? artifact.id,
                                value: artifact.id,
                              }
                              : undefined
                          }
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
                    setFieldValue={setFieldValue}
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
          obsContent {
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
        ... on Credential {
          value
        }
        ... on TrackingNumber {
          value
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
        ... on Persona {
          persona_name
          persona_type
        }
        ... on SSHKey {
          public_key
          key_type
          key_length
          fingerprint_sha256
          fingerprint_md5
          comment
          expiration_date
        }
        ... on IMEI {
          value
        }
        ... on ICCID {
          value
        }
        ... on IMSI {
          value
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
          id
          definition
          definition_type
          x_opencti_order
          x_opencti_color
        }
      }
    `,
  },
);

export default StixCyberObservableEditionOverview;
