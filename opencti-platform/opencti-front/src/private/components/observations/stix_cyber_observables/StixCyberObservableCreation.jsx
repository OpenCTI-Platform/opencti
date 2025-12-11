import React, { useEffect, useMemo, useState } from 'react';
import { Field, Form, Formik } from 'formik';
import Drawer from '@mui/material/Drawer';
import Typography from '@mui/material/Typography';
import Button from '@mui/material/Button';
import IconButton from '@mui/material/IconButton';
import Fab from '@mui/material/Fab';
import Alert from '@mui/lab/Alert';
import { Add, Close } from '@mui/icons-material';
import { dissoc, filter, fromPairs, includes, map, pipe, pluck, propOr, toPairs } from 'ramda';
import * as Yup from 'yup';
import { graphql } from 'react-relay';
import DialogTitle from '@mui/material/DialogTitle';
import DialogContent from '@mui/material/DialogContent';
import Dialog from '@mui/material/Dialog';
import List from '@mui/material/List';
import ListItemText from '@mui/material/ListItemText';
import makeStyles from '@mui/styles/makeStyles';
import { ListItemButton } from '@mui/material';
import PropTypes from 'prop-types';
import { useTheme } from '@mui/styles';
import { handleErrorInForm, QueryRenderer } from '../../../../relay/environment';
import TextField from '../../../../components/TextField';
import SwitchField from '../../../../components/fields/SwitchField';
import CreatedByField from '../../common/form/CreatedByField';
import ObjectLabelField from '../../common/form/ObjectLabelField';
import ObjectMarkingField from '../../common/form/ObjectMarkingField';
import { stixCyberObservablesLinesAttributesQuery, stixCyberObservablesLinesSubTypesQuery } from './StixCyberObservablesLines';
import { parse } from '../../../../utils/Time';
import MarkdownField from '../../../../components/fields/MarkdownField';
import { ExternalReferencesField } from '../../common/form/ExternalReferencesField';
import DateTimePickerField from '../../../../components/DateTimePickerField';
import ArtifactField from '../../common/form/ArtifactField';
import OpenVocabField from '../../common/form/OpenVocabField';
import { fieldSpacingContainerStyle } from '../../../../utils/field';
import { insertNode } from '../../../../utils/store';
import { useFormatter } from '../../../../components/i18n';
import useVocabularyCategory from '../../../../utils/hooks/useVocabularyCategory';
import { convertMarking } from '../../../../utils/edition';
import CustomFileUploader from '../../common/files/CustomFileUploader';
import useAttributes from '../../../../utils/hooks/useAttributes';
import useApiMutation from '../../../../utils/hooks/useApiMutation';
import CreateEntityControlledDial from '../../../../components/CreateEntityControlledDial';
import BulkTextModalButton from '../../../../components/fields/BulkTextField/BulkTextModalButton';
import BulkTextModal from '../../../../components/fields/BulkTextField/BulkTextModal';
import { splitMultilines } from '../../../../utils/String';
import ProgressBar from '../../../../components/ProgressBar';
import useBulkCommit from '../../../../utils/hooks/useBulkCommit';
import BulkTextField from '../../../../components/fields/BulkTextField/BulkTextField';

// Deprecated - https://mui.com/system/styles/basics/
// Do not use it for new code.
const useStyles = makeStyles((theme) => ({
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
    right: 30,
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
    backgroundColor: theme.palette.mode === 'light' ? theme.palette.background.default : theme.palette.background.nav,
    padding: '10px 0',
    paddingLeft: '5px',
    display: 'flex',
    alignItems: 'center',
    gap: '5px',
  },
  container: {
    padding: '10px 20px 20px 20px',
  },
}));

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
  stixCyberObservableTypes = undefined,
}) => {
  const classes = useStyles();
  const theme = useTheme();
  const { t_i18n } = useFormatter();
  const { isVocabularyField, fieldToCategory } = useVocabularyCategory();
  const { booleanAttributes, dateAttributes, multipleAttributes, numberAttributes, ignoredAttributes } = useAttributes();
  const [status, setStatus] = useState({ open: false, type: type ?? null });
  const inputObsType = useMemo(() => status?.type?.replace(/(?:^|-|_)(\w)/g, (_, l) => l.toUpperCase()), [status]);
  const [bulkOpen, setBulkOpen] = useState(false);
  const [progressBarOpen, setProgressBarOpen] = useState(false);

  const [bulkSelectedKey, setBulkSelectedKey] = useState(null);
  const bulkConf = useMemo(() => BULK_OBSERVABLES.find(({ type: obsType }) => obsType === status.type), [status]);
  useEffect(() => {
    setBulkSelectedKey(bulkConf?.keys.length === 1 ? bulkConf.keys[0] : null);
  }, [bulkConf]);

  const [commit] = useApiMutation(
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
  } = useBulkCommit({
    type: 'observables',
    commit,
    relayUpdater: (store) => {
      insertNode(
        store,
        paginationKey,
        paginationOptions,
        'stixCyberObservableAdd',
      );
    },
  });

  useEffect(() => {
    if (bulkCount > 1) {
      setProgressBarOpen(true);
    }
  }, [bulkCount]);

  const handleOpen = () => setStatus({ open: true, type: status.type });
  const localHandleClose = () => setStatus({ open: false, type: type ?? null });
  const selectType = (selected) => setStatus({ open: status.open, type: selected });

  const onSubmit = (values, { setSubmitting, setErrors, resetForm }) => {
    let adaptedValues = [values];
    if (bulkConf && bulkSelectedKey) {
      const allValues = splitMultilines(values[bulkSelectedKey]);
      adaptedValues = allValues.map((v) => ({
        ...values,
        [bulkSelectedKey]: v,
      }));
    }

    const finalValues = adaptedValues.map((val) => {
      let adaptedValue = val;
      // Potential dicts
      if (
        adaptedValue.hashes_MD5
        || adaptedValue['hashes_SHA-1']
        || adaptedValue['hashes_SHA-256']
        || adaptedValue['hashes_SHA-512']
      ) {
        adaptedValue.hashes = [];
        if (adaptedValue.hashes_MD5.length > 0) {
          adaptedValue.hashes.push({
            algorithm: 'MD5',
            hash: adaptedValue.hashes_MD5,
          });
        }
        if (adaptedValue['hashes_SHA-1'].length > 0) {
          adaptedValue.hashes.push({
            algorithm: 'SHA-1',
            hash: adaptedValue['hashes_SHA-1'],
          });
        }
        if (adaptedValue['hashes_SHA-256'].length > 0) {
          adaptedValue.hashes.push({
            algorithm: 'SHA-256',
            hash: adaptedValue['hashes_SHA-256'],
          });
        }
        if (adaptedValue['hashes_SHA-512'].length > 0) {
          adaptedValue.hashes.push({
            algorithm: 'SHA-512',
            hash: adaptedValue['hashes_SHA-512'],
          });
        }
      }
      // remove any non-numbers from imie on submit
      if (bulkConf.type === 'IMEI') {
        adaptedValue.value = adaptedValue.value.replace(/[^0-9]/g, '');
      }
      adaptedValue = pipe(
        dissoc('x_opencti_description'),
        dissoc('x_opencti_score'),
        dissoc('createdBy'),
        dissoc('objectMarking'),
        dissoc('objectLabel'),
        dissoc('externalReferences'),
        dissoc('createIndicator'),
        dissoc('hashes_MD5'),
        dissoc('hashes_SHA-1'),
        dissoc('hashes_SHA-256'),
        dissoc('hashes_SHA-512'),
        toPairs,
        map((n) => (includes(n[0], dateAttributes)
          ? [n[0], n[1] ? parse(n[1]).format() : null]
          : n)),
        map((n) => (includes(n[0], numberAttributes)
          ? [n[0], n[1] ? parseInt(n[1], 10) : null]
          : n)),
        map((n) => (includes(n[0], multipleAttributes)
          ? [n[0], n[1] ? n[1].split(',') : null]
          : n)),
        fromPairs,
      )(adaptedValue);

      const singularValue = {
        type: status.type,
        x_opencti_description:
          values.x_opencti_description.length > 0
            ? values.x_opencti_description
            : null,
        x_opencti_score: parseInt(values.x_opencti_score, 10),
        createdBy: propOr(null, 'value', values.createdBy),
        objectMarking: pluck('value', values.objectMarking),
        objectLabel: pluck('value', values.objectLabel),
        externalReferences: pluck('value', values.externalReferences),
        createIndicator: values.createIndicator,
        [inputObsType]: {
          ...adaptedValue,
          obsContent: values.obsContent?.value,
        },
      };
      if (values.file) {
        singularValue.file = values.file;
      }
      return singularValue;
    });

    bulkCommit({
      variables: finalValues,
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
        if (onCompleted) onCompleted();
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
        render={({ props }) => {
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
              <List>
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
        render={({ props }) => {
          if (props && props.schemaAttributeNames) {
            const baseCreatedBy = defaultCreatedBy
              ? { value: defaultCreatedBy.id, label: defaultCreatedBy.name }
              : undefined;
            const baseMarkingDefinitions = defaultMarkingDefinitions.map((n) => convertMarking(n));
            const initialValues = {
              x_opencti_description: '',
              x_opencti_score: 50,
              createdBy: baseCreatedBy,
              objectMarking: baseMarkingDefinitions,
              objectLabel: [],
              externalReferences: [],
              createIndicator: false,
              file: undefined,
            };
            const attributes = pipe(
              map((n) => n.node),
              filter(
                (n) => !includes(n.value, ignoredAttributes)
                  && !n.value.startsWith('i_'),
              ),
            )(props.schemaAttributeNames.edges);

            let extraFieldsToValidate = null;
            let requiredOneOfFields = [];
            for (const attribute of attributes) {
              if (isVocabularyField(status.type, attribute.value)) {
                initialValues[attribute.value] = null;
              } else if (includes(attribute.value, dateAttributes)) {
                initialValues[attribute.value] = null;
              } else if (includes(attribute.value, booleanAttributes)) {
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
                extraFieldsToValidate = {
                  hashes_MD5: Yup
                    .string().matches(md5Regex, t_i18n('MD5 values can only include A-F and 0-9, 32 characters'))
                    .when(['hashes_SHA-1', 'hashes_SHA-256', 'hashes_SHA-512', 'name'], {
                      is: (a, b, c, d) => !a && !b && !c && !d,
                      then: () => Yup.string().matches(md5Regex, t_i18n('MD5 values can only include A-F and 0-9, 32 characters')).required(t_i18n('MD5, SHA-1, SHA-256, SHA-512, or name is required')),
                    }),
                  'hashes_SHA-1': Yup
                    .string().matches(sha1Regex, t_i18n('SHA-1 values can only include A-F and 0-9, 40 characters'))
                    .when(['hashes_MD5', 'hashes_SHA-256', 'hashes_SHA-512', 'name'], {
                      is: (a, b, c, d) => !a && !b && !c && !d,
                      then: () => Yup.string().matches(sha1Regex, t_i18n('SHA-1 values can only include A-F and 0-9, 40 characters')).required(t_i18n('MD5, SHA-1, SHA-256, SHA-512, or name is required')),
                    }),
                  'hashes_SHA-256': Yup
                    .string().matches(sha256Regex, t_i18n('SHA-256 values can only include A-F and 0-9, 64 characters'))
                    .when(['hashes_MD5', 'hashes_SHA-1', 'hashes_SHA-512', 'name'], {
                      is: (a, b, c, d) => !a && !b && !c && !d,
                      then: () => Yup.string().matches(sha256Regex, t_i18n('SHA-256 values can only include A-F and 0-9, 64 characters')).required(t_i18n('MD5, SHA-1, SHA-256, SHA-512, or name is required')),
                    }),
                  'hashes_SHA-512': Yup
                    .string().matches(sha512Regex, t_i18n('SHA-512 values can only include A-F and 0-9, 128 characters'))
                    .when(['hashes_MD5', 'hashes_SHA-1', 'hashes_SHA-256', 'name'], {
                      is: (a, b, c, d) => !a && !b && !c && !d,
                      then: () => Yup.string().matches(sha512Regex, t_i18n('SHA-512 values can only include A-F and 0-9, 128 characters')).required(t_i18n('MD5, SHA-1, SHA-256, SHA-512, or name is required')),
                    }),
                  name: Yup
                    .string()
                    .when(['hashes_MD5', 'hashes_SHA-1', 'hashes_SHA-256', 'hashes_SHA-512'], {
                      is: (a, b, c, d) => !a && !b && !c && !d,
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
                const imeiRegex = /(\d{2})([^a-z\d]{1})?(\d{4})([^a-z\d]{1})?(\d{2})([^a-z\d]{1})?(\d{6})([^a-z\d]{1})?(\d{1,2})$/i;
                extraFieldsToValidate = {
                  [attribute.value]: Yup.string().required(t_i18n('This field is required')).matches(imeiRegex, t_i18n('IMEI values must be 15 to 16 digits. Special characters are accepted as delimiters.')),
                };
                requiredOneOfFields = [
                  [attribute.value],
                ];
              } else if (status.type === 'ICCID') {
                const iccidRegex = /(^[0-9]{18,22})$/i;
                extraFieldsToValidate = {
                  [attribute.value]: Yup.string().required(t_i18n('This field is required')).matches(iccidRegex, t_i18n('ICCID values can only include 0-9, 18 to 22 characters')),
                };
                requiredOneOfFields = [
                  [attribute.value],
                ];
              } else if (status.type === 'IMSI') {
                const imsiRegex = /(^[0-9]{14,15})$/i;
                extraFieldsToValidate = {
                  [attribute.value]: Yup.string().required(t_i18n('This field is required')).matches(imsiRegex, t_i18n('IMSI values can only include 0-9, 14 to 15 characters')),
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
            const stixCyberObservableValidation = () => Yup.object().shape({
              x_opencti_score: Yup.number().integer(t_i18n('The value must be an integer'))
                .nullable()
                .min(0, t_i18n('The value must be greater than or equal to 0'))
                .max(100, t_i18n('The value must be less than or equal to 100')),
              x_opencti_description: Yup.string().nullable(),
              createIndicator: Yup.boolean(),
            });

            const stixCyberObservableValidationFinal = Yup.object().shape({
              ...stixCyberObservableValidation,
              ...extraFieldsToValidate,
            }, requiredOneOfFields);

            if (isFromBulkRelation) {
              const foundEntityType = SCO_DEFAULT_FIELD.find((item) => item.type === status.type);
              if (foundEntityType) initialValues[foundEntityType.field] = inputValue;
            }

            const isFieldInBulk = (name) => name === bulkSelectedKey;

            return (
              <Formik
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
                }) => (
                  <>
                    {bulkConf && (
                      <>
                        <BulkTextModal
                          title={t_i18n('Create multiple observables')}
                          open={bulkOpen}
                          onClose={() => setBulkOpen(false)}
                          availableKeys={bulkConf?.keys.length > 1 ? bulkConf.keys : undefined}
                          onSelectKey={(key) => setBulkSelectedKey(key || null)}
                          selectedKey={bulkSelectedKey}
                          onValidate={async (val) => {
                            if (bulkSelectedKey) {
                              await setFieldValue(bulkSelectedKey, val);
                              if (splitMultilines(val).length > 1) {
                                await setFieldValue('file', null);
                              }
                            }
                          }}
                          formValue={values[bulkSelectedKey] ?? ''}
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
                          <BulkResult variablesToString={(v) => v[inputObsType][bulkSelectedKey]} />
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
                          if (bulkConf && attribute.value === bulkSelectedKey) {
                            return (
                              <Field
                                component={BulkTextField}
                                variant="standard"
                                name={attribute.value}
                                label={t_i18n(attribute.value)}
                                key={attribute.value}
                                fullWidth={true}
                                style={{ marginTop: 20 }}
                                bulkType='observables'
                              />
                            );
                          }
                          if (attribute.value === 'hashes') {
                            return (
                              <div key={attribute.value}>
                                <Field
                                  component={isFieldInBulk('hashes_MD5') ? BulkTextField : TextField}
                                  variant="standard"
                                  name="hashes_MD5"
                                  label={t_i18n('hash_md5')}
                                  fullWidth={true}
                                  style={{ marginTop: 20 }}
                                  bulkType='observables'
                                />
                                <Field
                                  component={isFieldInBulk('hashes_SHA-1') ? BulkTextField : TextField}
                                  variant="standard"
                                  name="hashes_SHA-1"
                                  label={t_i18n('hash_sha-1')}
                                  fullWidth={true}
                                  style={{ marginTop: 20 }}
                                  bulkType='observables'
                                />
                                <Field
                                  component={isFieldInBulk('hashes_SHA-256') ? BulkTextField : TextField}
                                  variant="standard"
                                  name="hashes_SHA-256"
                                  label={t_i18n('hash_sha-256')}
                                  fullWidth={true}
                                  style={{ marginTop: 20 }}
                                  bulkType='observables'
                                />
                                <Field
                                  component={isFieldInBulk('hashes_SHA-512') ? BulkTextField : TextField}
                                  variant="standard"
                                  name="hashes_SHA-512"
                                  label={t_i18n('hash_sha-512')}
                                  fullWidth={true}
                                  style={{ marginTop: 20 }}
                                  bulkType='observables'
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
                                )}
                                name={attribute.value}
                                onChange={(name, value) => setFieldValue(name, value)
                                }
                                containerStyle={fieldSpacingContainerStyle}
                                multiple={false}
                              />
                            );
                          }
                          if (includes(attribute.value, dateAttributes)) {
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
                          if (includes(attribute.value, numberAttributes)) {
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
                          if (includes(attribute.value, booleanAttributes)) {
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
                              label={t_i18n(attribute.value)}
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
                      <CustomFileUploader
                        setFieldValue={setFieldValue}
                        formikErrors={errors}
                        disabled={bulkConf && bulkSelectedKey && splitMultilines(values[bulkSelectedKey]).length > 1}
                        noFileSelectedLabel={bulkConf && bulkSelectedKey && splitMultilines(values[bulkSelectedKey]).length > 1
                          ? t_i18n('File upload not allowed in bulk creation')
                          : undefined
                        }
                      />
                      <Field
                        component={SwitchField}
                        type="checkbox"
                        name="createIndicator"
                        label={t_i18n('Create an indicator from this observable')}
                        containerstyle={{ marginTop: 20 }}
                      />
                      <div className={classes.buttons}>
                        {!isFromBulkRelation && (
                          <Button
                            variant={contextual ? 'text' : 'contained'}
                            onClick={() => selectType(null)}
                            disabled={isSubmitting}
                            classes={{ root: classes.button }}
                          >
                            {t_i18n('Back')}
                          </Button>
                        )}
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
                  </>
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
      <>
        <CreateEntityControlledDial
          entityType={type ?? 'Observable'}
          onOpen={handleOpen}
          onClose={() => {}}
          style={controlledDialStyles}
        />
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
            <Typography variant="subtitle2">{t_i18n('Create an observable')}</Typography>
            {!isFromBulkRelation && status.type
              ? <BulkTextModalButton
                  onClick={() => setBulkOpen(true)}
                  title={t_i18n('Create multiple observables')}
                  disabled={!bulkConf}
                />
              : <></>
            }
          </div>
          <div className={classes.container}>
            {!status.type ? renderList() : renderForm()}
          </div>
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
          <Fab
            onClick={handleOpen}
            color="primary"
            aria-label="Add"
            className={classes.createButtonContextual}
          >
            <Add />
          </Fab>
        )}
        <Dialog
          open={speeddial ? open : status.open}
          slotProps={{ paper: { elevation: 1 } }}
          onClose={speeddial ? handleClose : localHandleClose}
          fullWidth={true}
        >
          <DialogTitle style={{ display: 'flex' }}>
            {t_i18n('Create an observable')}
            {!isFromBulkRelation && status.type
              ? <BulkTextModalButton
                  sx={{ marginRight: 0 }}
                  onClick={() => setBulkOpen(true)}
                  title={t_i18n('Create multiple observables')}
                  disabled={!bulkConf}
                />
              : <></>
            }
          </DialogTitle>
          <DialogContent style={{ paddingTop: 0 }}>
            {renderUnavailableBulkMessage()}
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

StixCyberObservableCreation.propTypes = {
  contextual: PropTypes.bool.isRequired,
  open: PropTypes.bool,
  handleClose: PropTypes.func,
  type: PropTypes.string,
  display: PropTypes.bool,
  speeddial: PropTypes.bool,
  inputValue: PropTypes.string,
  paginationKey: PropTypes.string,
  paginationOptions: PropTypes.any,
  controlledDialStyles: PropTypes.object,
  defaultCreatedBy: PropTypes.oneOfType([
    PropTypes.shape({
      id: PropTypes.string.isRequired,
      name: PropTypes.string.isRequired,
    }),
    PropTypes.oneOf([undefined]),
  ]),
  defaultMarkingDefinitions: PropTypes.arrayOf(
    PropTypes.shape({
      id: PropTypes.string.isRequired,
      name: PropTypes.string.isRequired,
    }),
  ),
  isFromBulkRelation: PropTypes.bool,
  onCompleted: PropTypes.func,
  stixCyberObservableTypes: PropTypes.arrayOf(PropTypes.string),
};

export default StixCyberObservableCreation;
