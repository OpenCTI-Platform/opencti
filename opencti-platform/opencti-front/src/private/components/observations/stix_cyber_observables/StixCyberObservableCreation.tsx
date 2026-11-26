import Button from '@common/button/Button';
import IconButton from '@common/button/IconButton';
import Dialog from '@common/dialog/Dialog';
import FormButtonContainer from '@common/form/FormButtonContainer';
import Drawer from '@components/common/drawer/Drawer';
import { Add } from '@mui/icons-material';
import Alert from '@mui/material/Alert';
import { ListItemButton, Stack } from '@mui/material';
import List from '@mui/material/List';
import ListItemText from '@mui/material/ListItemText';
import { styled, useTheme } from '@mui/material/styles';
import { Field, Form, Formik, FormikConfig } from 'formik';
import React, { CSSProperties, useEffect, useMemo, useRef, useState } from 'react';
import { graphql } from 'react-relay';
import * as Yup from 'yup';
import CreateEntityControlledDial from '../../../../components/CreateEntityControlledDial';
import DateTimePickerField from '../../../../components/DateTimePickerField';
import ProgressBar from '../../../../components/ProgressBar';
import TextField from '../../../../components/TextField';
import BulkTextField from '../../../../components/fields/BulkTextField/BulkTextField';
import BulkTextModal from '../../../../components/fields/BulkTextField/BulkTextModal';
import BulkTextModalButton from '../../../../components/fields/BulkTextField/BulkTextModalButton';
import MarkdownField from '../../../../components/fields/markdownField/MarkdownField';
import SwitchField from '../../../../components/fields/SwitchField';
import { useFormatter } from '../../../../components/i18n';
import type { Theme } from '../../../../components/Theme';
import { handleErrorInForm, QueryRenderer } from '../../../../relay/environment';
import { splitMultilines } from '../../../../utils/String';
import { parse } from '../../../../utils/Time';
import { convertMarking } from '../../../../utils/edition';
import { FieldOption, fieldSpacingContainerStyle } from '../../../../utils/field';
import useApiMutation from '../../../../utils/hooks/useApiMutation';
import useAttributes from '../../../../utils/hooks/useAttributes';
import useBulkCommit from '../../../../utils/hooks/useBulkCommit';
import useVocabularyCategory from '../../../../utils/hooks/useVocabularyCategory';
import { useDeferredCreation } from '../../../../utils/hooks/useDeferredCreation';
import useMarkdownCreationFilesInput from '../../../../utils/markdown/useMarkdownCreationFilesInput';
import { insertNode } from '../../../../utils/store';
import CustomFileUploader from '../../common/files/CustomFileUploader';
import ArtifactField from '../../common/form/ArtifactField';
import CreatedByField from '../../common/form/CreatedByField';
import { ExternalReferencesField } from '../../common/form/ExternalReferencesField';
import ObjectLabelField from '../../common/form/ObjectLabelField';
import ObjectMarkingField from '../../common/form/ObjectMarkingField';
import OpenVocabField from '../../common/form/OpenVocabField';
import { CreatedObject } from '../../common/containers/useContainerObjects';
import type { DefaultValue } from '../../settings/sub_types/entity_setting/entitySetting';
import type { DefaultMarking } from '../../settings/marking_definitions/markingDefinition.types';
import { stixCyberObservablesLinesAttributesQuery, stixCyberObservablesLinesSubTypesQuery } from './StixCyberObservablesLines';
import {
  StixCyberObservableCreationMutation,
  StixCyberObservableCreationMutation$data,
  StixCyberObservableCreationMutation$variables,
} from './__generated__/StixCyberObservableCreationMutation.graphql';
import { StixCyberObservablesLinesSubTypesQuery$data } from './__generated__/StixCyberObservablesLinesSubTypesQuery.graphql';
import { StixCyberObservablesLinesAttributesQuery$data } from './__generated__/StixCyberObservablesLinesAttributesQuery.graphql';

const ContextualCreateButton = styled(IconButton)({
  position: 'fixed',
  bottom: 30,
  right: 30,
  zIndex: 2000,
});

const stixCyberObservableMutation = graphql`
  mutation StixCyberObservableCreationMutation(
    $type: String!
    $x_opencti_score: Int
    $x_opencti_description: String
    $createIndicator: Boolean
    $createdBy: String
    $objectMarking: [String]
    $objectLabel: [String]
    $externalReferences: [String]
    $AutonomousSystem: AutonomousSystemAddInput
    $Directory: DirectoryAddInput
    $DomainName: DomainNameAddInput
    $EmailAddr: EmailAddrAddInput
    $EmailMessage: EmailMessageAddInput
    $EmailMimePartType: EmailMimePartTypeAddInput
    $Artifact: ArtifactAddInput
    $StixFile: StixFileAddInput
    $X509Certificate: X509CertificateAddInput
    $IPv4Addr: IPv4AddrAddInput
    $IPv6Addr: IPv6AddrAddInput
    $MacAddr: MacAddrAddInput
    $Mutex: MutexAddInput
    $NetworkTraffic: NetworkTrafficAddInput
    $Process: ProcessAddInput
    $Software: SoftwareAddInput
    $Url: UrlAddInput
    $UserAccount: UserAccountAddInput
    $WindowsRegistryKey: WindowsRegistryKeyAddInput
    $WindowsRegistryValueType: WindowsRegistryValueTypeAddInput
    $Hostname: HostnameAddInput
    $CryptographicKey: CryptographicKeyAddInput
    $CryptocurrencyWallet: CryptocurrencyWalletAddInput
    $Text: TextAddInput
    $UserAgent: UserAgentAddInput
    $BankAccount: BankAccountAddInput
    $PhoneNumber: PhoneNumberAddInput
    $PaymentCard: PaymentCardAddInput
    $MediaContent: MediaContentAddInput
    $TrackingNumber: TrackingNumberAddInput
    $Credential: CredentialAddInput
    $Persona: PersonaAddInput
    $SSHKey: SSHKeyAddInput
    $AIPrompt: AIPromptAddInput
    $IMEI: IMEIAddInput
    $ICCID: ICCIDAddInput
    $IMSI: IMSIAddInput
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
      AutonomousSystem: $AutonomousSystem
      Directory: $Directory
      DomainName: $DomainName
      EmailAddr: $EmailAddr
      EmailMessage: $EmailMessage
      EmailMimePartType: $EmailMimePartType
      Artifact: $Artifact
      StixFile: $StixFile
      X509Certificate: $X509Certificate
      IPv4Addr: $IPv4Addr
      IPv6Addr: $IPv6Addr
      MacAddr: $MacAddr
      Mutex: $Mutex
      NetworkTraffic: $NetworkTraffic
      Process: $Process
      Software: $Software
      Url: $Url
      UserAccount: $UserAccount
      WindowsRegistryKey: $WindowsRegistryKey
      WindowsRegistryValueType: $WindowsRegistryValueType
      Hostname: $Hostname
      CryptographicKey: $CryptographicKey
      CryptocurrencyWallet: $CryptocurrencyWallet
      Text: $Text
      UserAgent: $UserAgent
      BankAccount: $BankAccount
      PhoneNumber: $PhoneNumber
      PaymentCard: $PaymentCard
      MediaContent: $MediaContent
      TrackingNumber: $TrackingNumber
      Credential: $Credential
      Persona: $Persona
      SSHKey: $SSHKey
      AIPrompt: $AIPrompt
      IMEI: $IMEI
      ICCID: $ICCID
      IMSI: $IMSI
    ) {
      id
      draftVersion {
        draft_id
        draft_operation
      }
      representative {
        main
      }
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
      creators {
        id,
        name,
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
      ... on Software {
        name
      }
      createdIndicator {
        id
        standard_id
        entity_type
        parent_types
        representative {
          main
        }
      }
    }
  }
`;

const BULK_OBSERVABLES = [
  { type: 'Credential', keys: ['value'] },
  { type: 'Cryptocurrency-Wallet', keys: ['value'] },
  { type: 'Cryptographic-Key', keys: ['value'] },
  { type: 'Domain-Name', keys: ['value'] },
  { type: 'Email-Addr', keys: ['value'] },
  { type: 'Hostname', keys: ['value'] },
  { type: 'ICCID', keys: ['value'] },
  { type: 'IMEI', keys: ['value'] },
  { type: 'IMSI', keys: ['value'] },
  { type: 'IPv4-Addr', keys: ['value'] },
  { type: 'IPv6-Addr', keys: ['value'] },
  { type: 'Mac-Addr', keys: ['value'] },
  { type: 'Phone-Number', keys: ['value'] },
  { type: 'Text', keys: ['value'] },
  { type: 'Tracking-Number', keys: ['value'] },
  { type: 'Url', keys: ['value'] },
  { type: 'User-Agent', keys: ['value'] },
  { type: 'AI-Prompt', keys: ['value'] },
  { type: 'StixFile', keys: ['name', 'hashes_MD5', 'hashes_SHA-1', 'hashes_SHA-256', 'hashes_SHA-512'] },
  { type: 'Artifact', keys: ['hashes_MD5', 'hashes_SHA-1', 'hashes_SHA-256', 'hashes_SHA-512'] },
  { type: 'X509-Certificate', keys: ['hashes_MD5', 'hashes_SHA-1', 'hashes_SHA-256', 'hashes_SHA-512'] },
];

const SCO_DEFAULT_FIELD = [
  { type: 'Bank-Account', field: 'iban' },
  { type: 'Autonomous-System', field: 'name' },
  { type: 'Directory', field: '' }, // Date ?
  { type: 'Email-Message', field: 'body' },
  { type: 'Email-Mime-Part-Type', field: 'body' },
  { type: 'Media-Content', field: '' }, // ?  Missing required elements for Media-Content creation (url) stixCyberObservableAdd(type: $type, x_opencti_score: $x_op
  { type: 'Mutex', field: 'name' },
  { type: 'Network-Traffic', field: 'dst_port' },
  { type: 'Payment-Card', field: 'card_number' },
  { type: 'Persona', field: 'persona_name' },
  { type: 'Process', field: 'command_line' },
  { type: 'Software', field: 'name' },
  { type: 'User-Account', field: 'account_login' },
  { type: 'Windows-Registry-Key', field: 'attribute_key' },
  { type: 'Windows-Registry-Value-Type', field: 'name' },
  { type: 'StixFile', field: 'name' },
  { type: 'Artifact', field: 'hashes_MD5' },
  { type: 'X509-Certificate', field: 'hashes_MD5' },
];

// Form fields sent at the root of the mutation, or only used to build the hashes: not part of the observable input
const NOT_OBSERVABLE_INPUT_FIELDS = [
  'x_opencti_description',
  'x_opencti_score',
  'createdBy',
  'objectMarking',
  'objectLabel',
  'externalReferences',
  'createIndicator',
  'hashes_MD5',
  'hashes_SHA-1',
  'hashes_SHA-256',
  'hashes_SHA-512',
];

const HASH_ALGORITHMS = ['MD5', 'SHA-1', 'SHA-256', 'SHA-512'];

export type CreatedObservable = NonNullable<StixCyberObservableCreationMutation$data['stixCyberObservableAdd']>;

// The attributes of the observable type are added to the form at run time
interface ObservableFormValues {
  x_opencti_description: string;
  x_opencti_score: number | string;
  createdBy: FieldOption | undefined;
  objectMarking: FieldOption[];
  objectLabel: FieldOption[];
  externalReferences: FieldOption[];
  createIndicator: boolean;
  file: File | null | undefined;
  obsContent?: FieldOption;
  [attribute: string]: unknown;
}

interface StixCyberObservableCreationProps {
  contextual: boolean;
  open?: boolean;
  handleClose?: () => void;
  type?: string;
  display?: boolean;
  speeddial?: boolean;
  inputValue?: string | null;
  paginationKey?: string;
  paginationOptions?: unknown;
  controlledDialStyles?: CSSProperties;
  defaultCreatedBy?: DefaultValue | null;
  defaultMarkingDefinitions?: readonly DefaultMarking[];
  isFromBulkRelation?: boolean;
  onCompleted?: (observable: CreatedObservable | null) => void;
  // Called for each observable created, also for each one of a bulk creation, with the indicator created with it ("Create indicator")
  onCreated?: (object: CreatedObject, options?: { indicator?: CreatedObject | null }) => void;
  stixCyberObservableTypes?: string[];
}

// The text of a form field, e.g. the values of a bulk creation
const fieldText = (values: ObservableFormValues, key: string | null): string => {
  const value = key ? values[key] : undefined;
  return typeof value === 'string' ? value : '';
};

const StixCyberObservableCreation = ({
  contextual,
  open = false,
  handleClose = () => {},
  type,
  display = false,
  speeddial = false,
  inputValue,
  paginationKey,
  paginationOptions = {},
  controlledDialStyles = {},
  defaultCreatedBy,
  defaultMarkingDefinitions = [],
  isFromBulkRelation = false,
  onCompleted = () => {},
  onCreated,
  stixCyberObservableTypes = undefined,
}: StixCyberObservableCreationProps) => {
  const theme = useTheme<Theme>();
  const { t_i18n } = useFormatter();
  const { isDeferredMode } = useDeferredCreation();
  const { isVocabularyField, fieldToCategory } = useVocabularyCategory();
  const { booleanAttributes, dateAttributes, multipleAttributes, numberAttributes, ignoredAttributes } = useAttributes();
  const [status, setStatus] = useState<{ open: boolean; type: string | null }>({ open: false, type: type ?? null });
  const inputObsType = useMemo(() => status?.type?.replace(/(?:^|-|_)(\w)/g, (_, l) => l.toUpperCase()) ?? '', [status]);
  const [bulkOpen, setBulkOpen] = useState(false);
  const [progressBarOpen, setProgressBarOpen] = useState(false);
  // The indicators created with the observables ("Create indicator"), for the bulk creation result
  const [createdIndicatorsCount, setCreatedIndicatorsCount] = useState(0);

  const [bulkSelectedKey, setBulkSelectedKey] = useState<string | null>(null);
  const bulkConf = useMemo(() => BULK_OBSERVABLES.find(({ type: obsType }) => obsType === status.type), [status]);
  // Store the latest created observable for callback
  const lastCreatedObservableRef = useRef<CreatedObservable | null>(null);

  useEffect(() => {
    setBulkSelectedKey(bulkConf?.keys.length === 1 ? bulkConf.keys[0] : null);
  }, [bulkConf]);

  const [commit] = useApiMutation<StixCyberObservableCreationMutation>(
    stixCyberObservableMutation,
    undefined,
    { successMessage: `${t_i18n('entity_Observable')} ${t_i18n('successfully created')}` },
  );

  const {
    bulkCommit,
    bulkCount,
    bulkCurrentCount,
    BulkResult,
    resetBulk,
  } = useBulkCommit<StixCyberObservableCreationMutation>({
    type: 'observables',
    commit,
    relayUpdater: (store, response) => {
      insertNode(
        store,
        paginationKey,
        paginationOptions,
        'stixCyberObservableAdd',
      );
      // Store the created observable for callback
      if (response?.stixCyberObservableAdd) {
        lastCreatedObservableRef.current = response.stixCyberObservableAdd;
      }
    },
  });
  const { buildCreationFilesInput, registerMarkdownImagesController } = useMarkdownCreationFilesInput();

  useEffect(() => {
    if (bulkCount > 1) {
      setProgressBarOpen(true);
    }
  }, [bulkCount]);

  const handleOpen = () => setStatus({ open: true, type: status.type });
  const localHandleClose = () => setStatus({ open: false, type: type ?? null });
  const selectType = (selected: string | null) => setStatus({ open: status.open, type: selected });

  // The observable input: the attributes of the observable type, converted to what the API expects
  const buildObservableInput = (formValues: ObservableFormValues) => {
    const hashes = HASH_ALGORITHMS
      .map((algorithm) => ({ algorithm, hash: fieldText(formValues, `hashes_${algorithm}`) }))
      .filter(({ hash }) => hash.length > 0);
    const hasHashFields = HASH_ALGORITHMS.some((algorithm) => !!formValues[`hashes_${algorithm}`]);
    const withHashes: Record<string, unknown> = hasHashFields ? { ...formValues, hashes } : { ...formValues };
    return Object.fromEntries(Object.entries(withHashes)
      .filter(([key]) => !NOT_OBSERVABLE_INPUT_FIELDS.includes(key))
      .map(([key, value]) => {
        let converted = value;
        if (dateAttributes.includes(key)) {
          converted = converted ? parse(converted as string).format() : null;
        }
        if (numberAttributes.includes(key)) {
          converted = converted ? parseInt(String(converted), 10) : null;
        }
        if (multipleAttributes.includes(key)) {
          converted = converted ? String(converted).split(',') : null;
        }
        return [key, converted];
      }));
  };

  const onSubmit: FormikConfig<ObservableFormValues>['onSubmit'] = (values, { setSubmitting, setErrors, resetForm }) => {
    setCreatedIndicatorsCount(0);
    let adaptedValues = [values];
    if (bulkConf && bulkSelectedKey) {
      const allValues = splitMultilines(fieldText(values, bulkSelectedKey));
      adaptedValues = allValues.map((v) => ({
        ...values,
        [bulkSelectedKey]: v,
      }));
    }

    const finalValues = adaptedValues.map((val) => {
      const singularValue: Record<string, unknown> = {
        type: status.type,
        x_opencti_description:
          values.x_opencti_description.length > 0
            ? values.x_opencti_description
            : null,
        x_opencti_score: parseInt(String(values.x_opencti_score), 10),
        createdBy: values.createdBy?.value ?? null,
        objectMarking: values.objectMarking.map(({ value }) => value),
        objectLabel: values.objectLabel.map(({ value }) => value),
        externalReferences: values.externalReferences.map(({ value }) => value),
        createIndicator: values.createIndicator,
        [inputObsType]: {
          ...buildObservableInput(val),
          ...buildCreationFilesInput(),
          obsContent: values.obsContent?.value,
        },
      };
      if (values.file) {
        singularValue.file = values.file;
      }
      // The observable input is keyed by the observable type, only known at run time
      return singularValue as unknown as StixCyberObservableCreationMutation$variables;
    });

    bulkCommit({
      variables: finalValues,
      onStepCompleted: (_, response) => {
        if (response?.stixCyberObservableAdd?.createdIndicator) {
          setCreatedIndicatorsCount((count) => count + 1);
        }
        if (onCreated && response?.stixCyberObservableAdd) {
          onCreated(response.stixCyberObservableAdd, { indicator: response.stixCyberObservableAdd.createdIndicator });
        }
      },
      onStepError: (error) => {
        handleErrorInForm(error, setErrors);
        setSubmitting(false);
      },
      onCompleted: (total) => {
        setSubmitting(false);
        if (total < 2) {
          // If > 2, this is calling when closing progress bar modal.
          resetForm();
          localHandleClose();
        }
        // Pass the created observable to the callback
        if (onCompleted) {
          onCompleted(lastCreatedObservableRef.current);
          lastCreatedObservableRef.current = null;
        }
      },
    });
  };

  const onReset = () => {
    if (speeddial) {
      handleClose();
      setStatus({ open: false, type: null });
    } else {
      localHandleClose();
    }
  };

  const renderList = () => {
    return (
      <QueryRenderer
        query={stixCyberObservablesLinesSubTypesQuery}
        variables={{ type: 'Stix-Cyber-Observable' }}
        render={({ props }: { props: StixCyberObservablesLinesSubTypesQuery$data | null }) => {
          if (props && props.subTypes) {
            const subTypesEdges = props.subTypes.edges;
            const translatedOrderedList = subTypesEdges
              .map((edge) => edge.node)
              .filter((node) => !stixCyberObservableTypes
                || stixCyberObservableTypes.includes(node.id))
              .map((node) => ({
                ...node,
                tlabel: t_i18n(`entity_${node.label}`),
              }))
              .sort((a, b) => a.tlabel.toLowerCase().localeCompare(b.tlabel.toLowerCase()));

            return (
              <List disablePadding>
                {translatedOrderedList.map((subType) => (
                  <ListItemButton
                    key={subType.label}
                    divider={true}
                    dense={true}
                    onClick={() => selectType(subType.label)}
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
  const renderForm = () => {
    return (
      <QueryRenderer
        query={stixCyberObservablesLinesAttributesQuery}
        variables={{ elementType: [status.type] }}
        render={({ props }: { props: StixCyberObservablesLinesAttributesQuery$data | null }) => {
          if (props && props.schemaAttributeNames) {
            const baseCreatedBy = defaultCreatedBy
              ? { value: defaultCreatedBy.id, label: defaultCreatedBy.name }
              : undefined;
            const baseMarkingDefinitions: FieldOption[] = defaultMarkingDefinitions.map((n) => convertMarking(n));
            const initialValues: ObservableFormValues = {
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
              .filter((n) => !ignoredAttributes.includes(n.value) && !n.value.startsWith('i_'));
            let extraFieldsToValidate: Yup.ObjectShape | null = null;
            let requiredOneOfFields: string[][] = [];
            for (const attribute of attributes) {
              if (isVocabularyField(status.type ?? undefined, attribute.value)) {
                initialValues[attribute.value] = null;
              } else if (dateAttributes.includes(attribute.value)) {
                initialValues[attribute.value] = null;
              } else if (booleanAttributes.includes(attribute.value)) {
                initialValues[attribute.value] = false;
              } else if (attribute.value === 'bic' || attribute.value === 'iban') {
                initialValues.bic = '';
                initialValues.iban = '';
                const bicregex = /^[A-Z]{6}[A-Z0-9]{2}([A-Z0-9]{3})?$/i;
                const ibanregex = /^[A-Z]{2}[0-9]{2}[A-Z0-9]{1,30}$/i;
                extraFieldsToValidate = {
                  bic: Yup.string()
                    .matches(bicregex, t_i18n('bic values can only include A-Z and 0-9, 8 or 11 characters')),
                  iban: Yup.mixed().when([], {
                    is: () => status.type === 'Bank-Account',
                    then: () => Yup.string().matches(ibanregex, t_i18n('iban values must begin with a country code and can only include A-Z and 0-9, 34 characters')).required(t_i18n('This field is required')),
                    otherwise: () => Yup.string().matches(ibanregex, t_i18n('iban values must begin with a country code and can only include A-Z and 0-9, 34 characters')),
                  }),

                };
              } else if (attribute.value === 'hashes') {
                initialValues.hashes_MD5 = '';
                initialValues['hashes_SHA-1'] = '';
                initialValues['hashes_SHA-256'] = '';
                initialValues['hashes_SHA-512'] = '';
                // Dynamically include validation options for File Hash Options.
                const md5Regex = /(^[a-fA-F0-9]{32})(?:\n[a-fA-F0-9]{32}){0,49}$/i;
                const sha1Regex = /(^[a-fA-F0-9]{40})(?:\n[a-fA-F0-9]{40}){0,49}$/i;
                const sha256Regex = /(^[a-fA-F0-9]{64})(?:\n[a-fA-F0-9]{64}){0,49}$/i;
                const sha512Regex = /(^[a-fA-F0-9]{128})(?:\n[a-fA-F0-9]{128}){0,49}$/i;
                const noneIsFilled = (a: unknown, b: unknown, c: unknown, d: unknown) => !a && !b && !c && !d;
                extraFieldsToValidate = {
                  hashes_MD5: Yup
                    .string().matches(md5Regex, t_i18n('MD5 values can only include A-F and 0-9, 32 characters'))
                    .when(['hashes_SHA-1', 'hashes_SHA-256', 'hashes_SHA-512', 'name'], {
                      is: noneIsFilled,
                      then: () => Yup.string().matches(md5Regex, t_i18n('MD5 values can only include A-F and 0-9, 32 characters')).required(t_i18n('MD5, SHA-1, SHA-256, SHA-512, or name is required')),
                    }),
                  'hashes_SHA-1': Yup
                    .string().matches(sha1Regex, t_i18n('SHA-1 values can only include A-F and 0-9, 40 characters'))
                    .when(['hashes_MD5', 'hashes_SHA-256', 'hashes_SHA-512', 'name'], {
                      is: noneIsFilled,
                      then: () => Yup.string().matches(sha1Regex, t_i18n('SHA-1 values can only include A-F and 0-9, 40 characters')).required(t_i18n('MD5, SHA-1, SHA-256, SHA-512, or name is required')),
                    }),
                  'hashes_SHA-256': Yup
                    .string().matches(sha256Regex, t_i18n('SHA-256 values can only include A-F and 0-9, 64 characters'))
                    .when(['hashes_MD5', 'hashes_SHA-1', 'hashes_SHA-512', 'name'], {
                      is: noneIsFilled,
                      then: () => Yup.string().matches(sha256Regex, t_i18n('SHA-256 values can only include A-F and 0-9, 64 characters')).required(t_i18n('MD5, SHA-1, SHA-256, SHA-512, or name is required')),
                    }),
                  'hashes_SHA-512': Yup
                    .string().matches(sha512Regex, t_i18n('SHA-512 values can only include A-F and 0-9, 128 characters'))
                    .when(['hashes_MD5', 'hashes_SHA-1', 'hashes_SHA-256', 'name'], {
                      is: noneIsFilled,
                      then: () => Yup.string().matches(sha512Regex, t_i18n('SHA-512 values can only include A-F and 0-9, 128 characters')).required(t_i18n('MD5, SHA-1, SHA-256, SHA-512, or name is required')),
                    }),
                  name: Yup
                    .string()
                    .when(['hashes_MD5', 'hashes_SHA-1', 'hashes_SHA-256', 'hashes_SHA-512'], {
                      is: noneIsFilled,
                      then: () => Yup.string().required(t_i18n('MD5, SHA-1, SHA-256, SHA-512, or name is required')),
                    }),
                  file: Yup.mixed().when([], {
                    is: () => status.type === 'Artifact',
                    then: () => Yup.mixed().required(t_i18n('This field is required')),
                    otherwise: () => Yup.mixed().nullable(),
                  }),
                };

                requiredOneOfFields = [
                  ['hashes_MD5', 'hashes_SHA-1'],
                  ['hashes_MD5', 'hashes_SHA-256'],
                  ['hashes_MD5', 'hashes_SHA-512'],
                  ['hashes_MD5', 'name'],
                  ['hashes_SHA-1', 'hashes_SHA-256'],
                  ['hashes_SHA-1', 'hashes_SHA-512'],
                  ['hashes_SHA-1', 'name'],
                  ['hashes_SHA-256', 'hashes_SHA-512'],
                  ['hashes_SHA-256', 'name'],
                  ['hashes_SHA-512', 'name'],
                ];
              } else if (status.type === 'IMEI') {
                const imeiRegex = /^([0-9]{15,16}\n*)+$/i;
                extraFieldsToValidate = {
                  [attribute.value]: Yup.string()
                    .required(t_i18n('This field is required'))
                    .matches(imeiRegex, t_i18n('IMEI values can only include digits, must be 15 to 16 characters')),
                };
                requiredOneOfFields = [
                  [attribute.value],
                ];
              } else if (status.type === 'ICCID') {
                const iccidRegex = /^([0-9]{18,22}\n*)+$/i;
                extraFieldsToValidate = {
                  [attribute.value]: Yup.string()
                    .required(t_i18n('This field is required'))
                    .matches(iccidRegex, t_i18n('ICCID values can only include digits, must be 18 to 22 characters')),
                };
                requiredOneOfFields = [
                  [attribute.value],
                ];
              } else if (status.type === 'IMSI') {
                const imsiRegex = /^([0-9]{14,15}\n*)+$/i;
                extraFieldsToValidate = {
                  [attribute.value]: Yup.string()
                    .required(t_i18n('This field is required'))
                    .matches(imsiRegex, t_i18n('IMSI values can only include digits, must be 14 to 15 characters')),
                };
                requiredOneOfFields = [
                  [attribute.value],
                ];
              } else if (attribute.value === 'value') {
                initialValues[attribute.value] = inputValue || '';
                // Dynamically include value field for Singular Observable type Object form validation
                extraFieldsToValidate = {
                  [attribute.value]: Yup.string().required(t_i18n('This field is required')),
                };
                requiredOneOfFields = [
                  [attribute.value],
                ];
              } else if (status.type === 'Autonomous-System') {
                extraFieldsToValidate = {
                  number: Yup.string().required(t_i18n('This field is required')),
                };
              } else if (status.type === 'Directory') {
                extraFieldsToValidate = {
                  path: Yup.string().required(t_i18n('This field is required')),
                };
              } else if (status.type === 'Email-Message') {
                extraFieldsToValidate = {
                  subject: Yup.string().required(t_i18n('This field is required')),
                };
              } else if (status.type === 'Media-Content') {
                extraFieldsToValidate = {
                  url: Yup.string().required(t_i18n('This field is required')),
                };
              } else if (status.type === 'Mutex') {
                extraFieldsToValidate = {
                  name: Yup.string().required(t_i18n('This field is required')),
                };
              } else if (status.type === 'Network-Traffic') {
                extraFieldsToValidate = {
                  src_port: Yup.string().required(t_i18n('This field is required')),
                };
              } else if (status.type === 'Payment-Card') {
                extraFieldsToValidate = {
                  card_number: Yup.string().required(t_i18n('This field is required')),
                  expiration_date: Yup.mixed().when([], {
                    is: () => attribute.value === 'expiration_date',
                    then: () => Yup.date().required(t_i18n('This field is required')),
                    otherwise: () => Yup.mixed().nonNullable(),
                  }),
                };
              } else if (status.type === 'Persona') {
                extraFieldsToValidate = {
                  persona_type: Yup.mixed().when([], {
                    is: () => attribute.value === 'persona_type',
                    then: () => Yup.mixed().required(t_i18n('This field is required')),
                    otherwise: () => Yup.mixed().nonNullable(),
                  }),
                  persona_name: Yup.mixed().required(t_i18n('This field is required')),
                };
              } else if (status.type === 'Process') {
                extraFieldsToValidate = {
                  command_line: Yup.string().required(t_i18n('This field is required')),
                };
              } else if (status.type === 'User-Account') {
                extraFieldsToValidate = {
                  account_type: Yup.mixed().required(t_i18n('This field is required')),
                  user_id: Yup.string().required(t_i18n('This field is required')),
                  account_login: Yup.string().required(t_i18n('This field is required')),
                };
              } else if (status.type === 'Windows-Registry-Key') {
                extraFieldsToValidate = {
                  attribute_key: Yup.mixed().required(t_i18n('This field is required')),
                };
              } else if (status.type === 'SSH-Key') {
                extraFieldsToValidate = {
                  fingerprint_sha256: Yup.mixed().required(t_i18n('This field is required')),
                };
              } else {
                initialValues[attribute.value] = '';
              }
            }

            const stixCyberObservableValidationFinal = Yup.object().shape(
              { ...extraFieldsToValidate },
              // Pairs of fields that depend on each other; a single field has no dependency
              requiredOneOfFields as [string, string][],
            );

            if (isFromBulkRelation) {
              const foundEntityType = SCO_DEFAULT_FIELD.find((item) => item.type === status.type);
              if (foundEntityType) initialValues[foundEntityType.field] = inputValue;
            }

            const isFieldInBulk = (name: string) => name === bulkSelectedKey;
            return (
              <Formik<ObservableFormValues>
                initialValues={initialValues}
                validationSchema={stixCyberObservableValidationFinal}
                onSubmit={onSubmit}
                onReset={onReset}
              >
                {({
                  submitForm,
                  handleReset,
                  isSubmitting,
                  setFieldValue,
                  values,
                  resetForm,
                  errors,
                }) => {
                  const isBulkWithSeveralValues = !!bulkConf && !!bulkSelectedKey
                    && splitMultilines(fieldText(values, bulkSelectedKey)).length > 1;
                  return (
                    <>
                      {bulkConf && (
                        <>
                          <BulkTextModal
                            title={t_i18n('Create multiple observables')}
                            open={bulkOpen}
                            onClose={() => setBulkOpen(false)}
                            availableKeys={bulkConf.keys.length > 1 ? bulkConf.keys : undefined}
                            onSelectKey={(key) => setBulkSelectedKey(key || null)}
                            selectedKey={bulkSelectedKey ?? undefined}
                            onValidate={async (val) => {
                              if (bulkSelectedKey) {
                                await setFieldValue(bulkSelectedKey, val);
                                if (splitMultilines(val).length > 1) {
                                  await setFieldValue('file', null);
                                }
                              }
                            }}
                            formValue={fieldText(values, bulkSelectedKey)}
                          />
                          <ProgressBar
                            open={progressBarOpen}
                            value={(bulkCurrentCount / bulkCount) * 100}
                            label={`${bulkCurrentCount}/${bulkCount}`}
                            title={t_i18n('Create multiple observables')}
                            onClose={() => {
                              setProgressBarOpen(false);
                              resetForm();
                              resetBulk();
                              localHandleClose();
                            }}
                          >
                            <BulkResult
                              variablesToString={(v) => {
                                const observableInput = (v as unknown as Record<string, Record<string, unknown> | undefined>)[inputObsType];
                                return String(observableInput?.[bulkSelectedKey ?? ''] ?? '');
                              }}
                              extraResults={createdIndicatorsCount > 0 ? [`${createdIndicatorsCount} ${t_i18n('indicators created')}`] : []}
                            />
                          </ProgressBar>
                        </>
                      )}
                      <Form
                        style={{
                          margin: contextual ? `${theme.spacing(1)} 0 0 0` : `${theme.spacing(1)} 0`,
                        }}
                      >
                        <div>
                          <Field
                            component={TextField}
                            variant="outlined"
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
                            autoPersistOnBlur={false}
                            registerMarkdownImagesController={registerMarkdownImagesController}
                            uploadFileMarkings={values.objectMarking.map(({ value }) => value)}
                          />
                          {attributes.map((attribute) => {
                            const isValueAttribute = attribute.value === 'value';
                            const attributeLabel = isValueAttribute
                              ? t_i18n('Value')
                              : t_i18n(attribute.value);
                            if (bulkConf && attribute.value === bulkSelectedKey) {
                              return (
                                <Field
                                  component={BulkTextField}
                                  variant="outlined"
                                  name={attribute.value}
                                  label={attributeLabel}
                                  key={attribute.value}
                                  required={isValueAttribute}
                                  fullWidth={true}
                                  style={{ marginTop: 20 }}
                                  bulkType="observables"
                                />
                              );
                            }
                            if (attribute.value === 'hashes') {
                              return (
                                <div key={attribute.value}>
                                  <Field
                                    component={isFieldInBulk('hashes_MD5') ? BulkTextField : TextField}
                                    variant="outlined"
                                    name="hashes_MD5"
                                    label={t_i18n('hash_md5')}
                                    fullWidth={true}
                                    style={{ marginTop: 20 }}
                                    bulkType="observables"
                                  />
                                  <Field
                                    component={isFieldInBulk('hashes_SHA-1') ? BulkTextField : TextField}
                                    variant="outlined"
                                    name="hashes_SHA-1"
                                    label={t_i18n('hash_sha-1')}
                                    fullWidth={true}
                                    style={{ marginTop: 20 }}
                                    bulkType="observables"
                                  />
                                  <Field
                                    component={isFieldInBulk('hashes_SHA-256') ? BulkTextField : TextField}
                                    variant="outlined"
                                    name="hashes_SHA-256"
                                    label={t_i18n('hash_sha-256')}
                                    fullWidth={true}
                                    style={{ marginTop: 20 }}
                                    bulkType="observables"
                                  />
                                  <Field
                                    component={isFieldInBulk('hashes_SHA-512') ? BulkTextField : TextField}
                                    variant="outlined"
                                    name="hashes_SHA-512"
                                    label={t_i18n('hash_sha-512')}
                                    fullWidth={true}
                                    style={{ marginTop: 20 }}
                                    bulkType="observables"
                                  />
                                </div>
                              );
                            }
                            const vocabularyCategory = fieldToCategory(status.type ?? undefined, attribute.value);
                            if (vocabularyCategory) {
                              return (
                                <OpenVocabField
                                  key={attribute.value}
                                  label={t_i18n(attribute.value)}
                                  type={vocabularyCategory}
                                  name={attribute.value}
                                  onChange={(name, value) => setFieldValue(name, value)}
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
                                    variant: 'outlined',
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
                                  variant="outlined"
                                  key={attribute.value}
                                  name={attribute.value}
                                  label={attribute.value}
                                  fullWidth={true}
                                  type="number"
                                  className="mt-5"
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
                            if (
                              attribute.value === 'name'
                              && status.type === 'Autonomous-System'
                            ) {
                              const setDefaultAutonomousSystemId = (_: string, value: string) => {
                                const match = value.match(/^as(\d+)$/i);
                                if (match && !values.number) {
                                  setFieldValue('number', parseInt(match[1], 10));
                                }
                              };
                              return (
                                <Field
                                  component={TextField}
                                  variant="outlined"
                                  key={attribute.value}
                                  name={attribute.value}
                                  label={t_i18n(attribute.value)}
                                  fullWidth={true}
                                  className="mt-5"
                                  onSubmit={setDefaultAutonomousSystemId}
                                />
                              );
                            }
                            return (
                              <Field
                                component={TextField}
                                variant="outlined"
                                key={attribute.value}
                                name={attribute.value}
                                label={attributeLabel}
                                required={isValueAttribute}
                                fullWidth={true}
                                className="mt-5"
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
                        <CustomFileUploader
                          setFieldValue={setFieldValue}
                          formikErrors={{ file: typeof errors.file === 'string' ? errors.file : undefined }}
                          disabled={isBulkWithSeveralValues}
                          noFileSelectedLabel={isBulkWithSeveralValues
                            ? t_i18n('File upload not allowed in bulk creation')
                            : undefined
                          }
                        />
                        {!isDeferredMode && (
                          <Field
                            component={SwitchField}
                            type="checkbox"
                            name="createIndicator"
                            label={t_i18n('Create an indicator from this observable')}
                            containerstyle={{ marginTop: 20 }}
                          />
                        )}
                        <FormButtonContainer>
                          {!isFromBulkRelation && (
                            <Button
                              variant="secondary"
                              onClick={() => selectType(null)}
                              disabled={isSubmitting}
                            >
                              {t_i18n('Back')}
                            </Button>
                          )}
                          <Button
                            variant="secondary"
                            onClick={handleReset}
                            disabled={isSubmitting}
                          >
                            {t_i18n('Cancel')}
                          </Button>
                          <Button
                            onClick={submitForm}
                            disabled={isSubmitting}
                          >
                            {t_i18n('Create')}
                          </Button>
                        </FormButtonContainer>
                      </Form>
                    </>
                  );
                }}
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
      <>
        <CreateEntityControlledDial
          entityType={type ?? 'Observable'}
          onOpen={handleOpen}
          onClose={() => {}}
          style={controlledDialStyles}
        />
        <Drawer
          open={status.open}
          onClose={localHandleClose}
          title={t_i18n('Create an observable')}
          header={
            !isFromBulkRelation && status.type
              ? (
                  <BulkTextModalButton
                    onClick={() => setBulkOpen(true)}
                    title={t_i18n('Create multiple observables')}
                    disabled={!bulkConf}
                  />
                )
              : <></>
          }
        >
          {!status.type ? renderList() : renderForm()}
        </Drawer>
      </>
    );
  };

  const renderUnavailableBulkMessage = () => {
    if (isFromBulkRelation && !bulkConf) {
      return (
        <Alert
          severity="info"
          variant="outlined"
          style={{ marginBottom: 10 }}
        >
          {t_i18n('This entity has several key fields, which is incompatible with bulk creation')}
        </Alert>
      );
    }
    return null;
  };

  const renderContextual = () => {
    return (
      <div style={{ display: display ? 'block' : 'none' }}>
        {!speeddial && (
          <ContextualCreateButton
            onClick={handleOpen}
            aria-label="Add"
            variant="tertiary"
            size="small"
          >
            <Add />
          </ContextualCreateButton>
        )}
        <Dialog
          open={speeddial ? open : status.open}
          onClose={speeddial ? handleClose : localHandleClose}
          title={(
            <Stack
              direction="row"
              sx={{
                alignItems: 'center',
                justifyContent: 'space-between',
              }}
            >
              {t_i18n('Create an observable')}
              {!isFromBulkRelation && status.type
                ? (
                    <BulkTextModalButton
                      onClick={() => setBulkOpen(true)}
                      title={t_i18n('Create multiple observables')}
                      disabled={!bulkConf}
                    />
                  )
                : <></>
              }
            </Stack>
          )}
        >
          {renderUnavailableBulkMessage()}
          {!status.type ? renderList() : renderForm()}
        </Dialog>
      </div>
    );
  };

  if (contextual) {
    return renderContextual();
  }
  return renderClassic();
};

export default StixCyberObservableCreation;
