import React, { useState } from 'react';
import { Field, Form, Formik } from 'formik';
import Drawer from '@mui/material/Drawer';
import Typography from '@mui/material/Typography';
import Button from '@mui/material/Button';
import IconButton from '@mui/material/IconButton';
import Fab from '@mui/material/Fab';
import { Add, Close } from '@mui/icons-material';
import { assoc, compose, dissoc, filter, fromPairs, includes, map, pipe, pluck, prop, propOr, sortBy, toLower, toPairs } from 'ramda';
import * as Yup from 'yup';
import { graphql } from 'react-relay';
import DialogTitle from '@mui/material/DialogTitle';
import DialogContent from '@mui/material/DialogContent';
import Tooltip from '@mui/material/Tooltip';
import PropTypes from 'prop-types';
import Dialog from '@mui/material/Dialog';
import List from '@mui/material/List';
import ListItemText from '@mui/material/ListItemText';
import makeStyles from '@mui/styles/makeStyles';
import { ListItemButton } from '@mui/material';
import { commitMutation, handleErrorInForm, QueryRenderer, MESSAGING$, commitMutationWithPromise } from '../../../../relay/environment';
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
import ProgressDialogContainer, { progressDialogStats } from '../../../../components/ProgressDialog';
import BulkAddComponent from '../../../../components/BulkAddComponent';

// Sleep Function used to:
// Impacting User Perceived Performance (UPP) to see progress bar movement and encourage
// the use of the System Import. This was discussed at one point - but is maybe no longer
// a requirement. This can be removed after testing, if desired, or left in with the purpose
// of forcing the user to see progress.
// eslint-disable-next-line no-promise-executor-return
const sleepCustomFunction = (ms = 0) => new Promise((resolve) => setTimeout(resolve, ms));

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
      ... on Software {
        name
      }
    }
  }
`;

const StixCyberObservableCreation = ({
  contextual,
  open,
  handleClose,
  type,
  display,
  speeddial,
  inputValue,
  paginationKey,
  paginationOptions,
  defaultCreatedBy = null,
  defaultMarkingDefinitions = null,
}) => {
  const classes = useStyles();
  const { t_i18n } = useFormatter();
  const { isVocabularyField, fieldToCategory } = useVocabularyCategory();
  const { booleanAttributes, dateAttributes, multipleAttributes, numberAttributes, ignoredAttributes } = useAttributes();
  const [status, setStatus] = useState({ open: false, type: type ?? null });
  const [openProgressDialog, setOpenProgressDialog] = useState(false);
  const handleOpen = () => setStatus({ open: true, type: status.type });
  const localHandleClose = () => setStatus({ open: false, type: type ?? null });
  const selectType = (selected) => setStatus({ open: status.open, type: selected });
  const [genericValueFieldDisabled, setGenericValueFieldDisabled] = useState(false);
  const bulkAddMsg = t_i18n('Multiple values entered. Edit with the TT button');
  const [genericValueFieldValue, setGenericValueFieldValue] = React.useState('');
  const [bulkValueFieldValue, setBulkValueFieldValue] = React.useState('');
  const [openBulkModal, setOpenBulkModal] = React.useState(false);
  let totalObservables = 0;

  const progressReset = () => {
    setOpenProgressDialog(false);
    progressDialogStats.resetCurrentIncrement();
    progressDialogStats.resetCurrentMaxIncrement(100);
    progressDialogStats.resetSuccessCount();
    progressDialogStats.resetErrorCount();
    progressDialogStats.setBatchingCompleted(false);
    progressDialogStats.setBatchingCancelled(false);
    setGenericValueFieldValue('');
    setBulkValueFieldValue('');
    totalObservables = 0;
  };
  const handleClickCloseProgress = () => {
    setOpenProgressDialog(false);
    progressDialogStats.setBatchingCancelled(true);
  };
  const onSubmit = (values, { setSubmitting, setErrors, resetForm }) => {
    let adaptedValues = values;
    function handlePromiseResult(valueList) {
      totalObservables = valueList.length;
      let closeFormWithAnySuccess = false;
      if (progressDialogStats.getBatchingCompleted() === true) {
        if (progressDialogStats.getErrorCount() > 0) {
          let message_string = '';
          if (progressDialogStats.getSuccessCount() > 0) {
            message_string = `${progressDialogStats.getSuccessCount()}/${totalObservables} ${t_i18n('were added successfully.')}`;
            closeFormWithAnySuccess = true;
          }
          message_string += ` ${progressDialogStats.getErrorCount()}/${totalObservables} ${t_i18n('observables contained errors and were not added.')} `;
          const consolidated_errors = { res: { errors: [{ message: '' }] } };
          // Short Error message, just has total success and failure counts with translation support
          consolidated_errors.res.errors[0].message = message_string;
          handleErrorInForm(consolidated_errors, setErrors);
          const combinedObservables = progressDialogStats.getSuccessCount() + progressDialogStats.getErrorCount();
          if (combinedObservables === totalObservables && progressDialogStats.getBatchingCompleted() === true) {
            progressReset();
          }
        } else {
          let bulk_success_message = `${progressDialogStats.getSuccessCount()}/${totalObservables} ${t_i18n('were added successfully.')}`;
          if (totalObservables === 1) {
            // This is for consistent messaging when adding just (1) Observable
            bulk_success_message = t_i18n('Observable successfully added');
            progressDialogStats.setBatchingCompleted(true);
            progressReset();
          }
          // Toast Message on Bulk Add Success
          MESSAGING$.notifySuccess(bulk_success_message);
          closeFormWithAnySuccess = true;
        }
      }
      // Close the form if any observables were successfully added.
      if (closeFormWithAnySuccess === true && progressDialogStats.getBatchingCompleted() === true) {
        setGenericValueFieldDisabled(false);
        localHandleClose();
        setOpenProgressDialog(false);
        progressReset();
      }
    }
    function updateProgress(position, batchSize) {
      if (position % batchSize === 0) {
        progressDialogStats.setCurrentIncrement(1);
      }
    }
    async function processPromises(chunkValueList, observableType, finalValues, position, batchSize, valueList) {
      // If batching has not been cancelled with the close button on the progress widget - continue processing
      if (!progressDialogStats.getBatchingCancelled()) {
        const promises = chunkValueList.map((value) => commitMutationWithPromise({
          mutation: stixCyberObservableMutation,
          variables: {
            ...finalValues,
            [observableType]: {
              ...adaptedValues,
              obsContent: values.obsContent?.value,
              value,
            },
          },
          updater: (store) => insertNode(
            store,
            paginationKey,
            paginationOptions,
            'stixCyberObservableAdd',
          ),
          onCompleted: () => {
            setSubmitting(false);
            resetForm();
            localHandleClose();
          },
          onError: () => {
            setSubmitting(false);
          },
        }));
        // Send out a batchSize of promises and await their return
        await Promise.allSettled(promises).then((results) => {
          results.forEach(({ status: promiseStatus }) => {
            if (promiseStatus === 'fulfilled') {
              progressDialogStats.updateSuccessCount(1);
            } else {
              progressDialogStats.updateErrorCount(1);
            }
          });
        });
        // Update progress based on batchSize returned
        updateProgress(position, batchSize);
        handlePromiseResult(valueList);
      }
    }
    if (adaptedValues) { // Verify not null for DeepScan compliance
      // Bulk Add Modal was used
      if (adaptedValues.bulk_value_field && (adaptedValues.value || genericValueFieldValue === bulkAddMsg)) {
        const array_of_bulk_values = adaptedValues.bulk_value_field.split(/\r?\n/);
        // Trim them just to remove any extra spacing on front or rear of string
        const trimmed_bulk_values = array_of_bulk_values.map((s) => s.trim());
        // Remove any "" or empty resulting elements
        const cleaned_bulk_values = trimmed_bulk_values.reduce((elements, i) => (i ? [...elements, i] : elements), []);
        // De-duplicate by unique then rejoin
        adaptedValues.value = [...new Set(cleaned_bulk_values)].join('\n');
      }

      // Potential dicts
      if (
        adaptedValues.hashes_MD5
        || adaptedValues['hashes_SHA-1']
        || adaptedValues['hashes_SHA-256']
        || adaptedValues['hashes_SHA-512']
      ) {
        adaptedValues.hashes = [];
        if (adaptedValues.hashes_MD5.length > 0) {
          adaptedValues.hashes.push({
            algorithm: 'MD5',
            hash: adaptedValues.hashes_MD5,
          });
        }
        if (adaptedValues['hashes_SHA-1'].length > 0) {
          adaptedValues.hashes.push({
            algorithm: 'SHA-1',
            hash: adaptedValues['hashes_SHA-1'],
          });
        }
        if (adaptedValues['hashes_SHA-256'].length > 0) {
          adaptedValues.hashes.push({
            algorithm: 'SHA-256',
            hash: adaptedValues['hashes_SHA-256'],
          });
        }
        if (adaptedValues['hashes_SHA-512'].length > 0) {
          adaptedValues.hashes.push({
            algorithm: 'SHA-512',
            hash: adaptedValues['hashes_SHA-512'],
          });
        }
      }
      adaptedValues = pipe(
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
      )(adaptedValues);
      const observableType = status.type.replace(/(?:^|-|_)(\w)/g, (matches, letter) => letter.toUpperCase());
      const finalValues = {
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
        [observableType]: {
          ...adaptedValues,
          obsContent: values.obsContent?.value,
        },
      };
      if (values.file) {
        finalValues.file = values.file;
      }

      const commit = async () => {
        const valueList = values?.value !== '' ? values?.value?.split('\n') || values?.value : undefined;
        // Launch Progress Bar, as value data is about to be processed.
        // Only need Progress Bar, if more than 1 element being processed
        if (valueList !== undefined && valueList.length > 1) {
          setOpenProgressDialog(true);
        }
        if (valueList) {
          delete adaptedValues.value;
          delete adaptedValues.bulk_value_field;
          const batchSize = 5;
          let currentBatch = 0;
          let position = 0;
          // Determine the number of batches required to help compute % complete rate
          const totalBatches = Math.ceil(valueList.length / batchSize);
          progressDialogStats.resetCurrentMaxIncrement(totalBatches);
          while (position < valueList.length) {
            const chunkValueList = valueList.slice(position, position + batchSize);
            currentBatch += 1;
            if (currentBatch === totalBatches) {
              progressDialogStats.setBatchingCompleted(true);
            }
            processPromises(chunkValueList, observableType, finalValues, position, batchSize, valueList);
            position += batchSize;
            if (progressDialogStats.getBatchingCancelled()) {
              position = valueList.length + 1; // Stop looping by moving position to end due to cancel button clicked
              progressReset();
            }
            // Impacting User Perceived Performance (UPP) to see progress bar movement and encourage
            // the use of the System Import. This was discussed at one point - but is maybe no longer
            // a requirement. This can be removed after testing, if desired, or left in with the purpose
            // of forcing the user to see progress.
            await sleepCustomFunction(2000); // eslint-disable-line no-await-in-loop
          }
        } else {
          // No 'values' were submitted to save, but other parts of form were possibly filled out for different
          // Observable type like File Hash or something that are not currently bulk addable.
          // No promise required here, just send the data for saving, as it is a singular add
          commitMutation({
            mutation: stixCyberObservableMutation,
            variables: finalValues,
            updater: (store) => insertNode(
              store,
              paginationKey,
              paginationOptions,
              'stixCyberObservableAdd',
            ),
            onError: (error) => {
              handleErrorInForm(error, setErrors);
              setSubmitting(false);
            },
            setSubmitting,
            onCompleted: () => {
              // Toast Message on Add Success
              MESSAGING$.notifySuccess(t_i18n('Observable successfully added'));
              setSubmitting(false);
              resetForm();
              setGenericValueFieldDisabled(false);
              localHandleClose();
            },
          });
        }
      };
      commit();
    }
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
            const sortByLabel = sortBy(compose(toLower, prop('tlabel')));
            const translatedOrderedList = pipe(
              map((n) => n.node),
              map((n) => assoc('tlabel', t_i18n(`entity_${n.label}`), n)),
              sortByLabel,
            )(subTypesEdges);
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

  function BulkAdd(props) {
    const handleOpenBulkModal = () => {
      if (genericValueFieldValue != null && genericValueFieldValue.length > 0 && genericValueFieldValue !== bulkAddMsg) {
        // Trim the field to avoid inserting whitespace as a default population value
        setBulkValueFieldValue(genericValueFieldValue.trim());
      }
      setOpenBulkModal(true);
    };
    const handleCloseBulkModal = (val) => {
      setOpenBulkModal(false);
      if (val != null && val.length > 0) {
        setBulkValueFieldValue(val);
        // Clear Attached File marker used by CustomFileUploader interaction to indicate a file need processing
        props.setValue('file', null);
        // This will disable the file upload button in addition disabling the value box for direct input.
        setGenericValueFieldDisabled(true);
        // Swap value box message to display that TT was used to input multiple values.
        setGenericValueFieldValue(bulkAddMsg);
      } else {
        setBulkValueFieldValue('');
        setGenericValueFieldValue('');
        setGenericValueFieldDisabled(false);
      }
    };
    const localHandleCancelClearBulkModal = () => {
      setOpenBulkModal(false);
      if (!genericValueFieldDisabled) {
        // If one-liner field isn't disabled, then you are it seems deciding
        // not to use the bulk add feature, so we will clear the field, since its population
        // is used to process the bul_value_field versus the generic_value_field
        setBulkValueFieldValue('');
        setGenericValueFieldValue('');
      }
      // else - you previously entered data and you just are canceling out of the popup window
      // but keeping your entry in the form.
    };
    return (
      <BulkAddComponent
        openBulkModal={openBulkModal}
        bulkValueFieldValue={bulkValueFieldValue}
        handleOpenBulkModal={handleOpenBulkModal}
        handleCloseBulkModal={handleCloseBulkModal}
        localHandleCancelClearBulkModal={localHandleCancelClearBulkModal}
      />
    );
  }
  BulkAdd.propTypes = {
    setValue: PropTypes.func,
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
            const baseMarkingDefinitions = (
              defaultMarkingDefinitions ?? []
            ).map((n) => convertMarking(n));
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
              } else if (attribute.value === 'hashes') {
                initialValues.hashes_MD5 = '';
                initialValues['hashes_SHA-1'] = '';
                initialValues['hashes_SHA-256'] = '';
                initialValues['hashes_SHA-512'] = '';
                // Dynamically include validation options for File Hash Options.
                const md5Regex = /^[a-f0-9]{32}$/i;
                const sha1Regex = /^[a-f0-9]{40}$/i;
                const sha256Regex = /^[a-f0-9]{64}$/i;
                const sha512Regex = /^[a-f0-9]{128}$/i;
                extraFieldsToValidate = {
                  hashes_MD5: Yup
                    .string()
                    .when(['hashes_SHA-1', 'hashes_SHA-256', 'hashes_SHA-512', 'name'], {
                      is: (a, b, c, d) => !a && !b && !c && !d,
                      then: () => Yup.string().matches(md5Regex, t_i18n('MD5 values can only include A-F and 0-9, 32 characters')).required(t_i18n('MD5, SHA-1, SHA-256, SHA-512, or name is required')),
                    }),
                  'hashes_SHA-1': Yup
                    .string()
                    .when(['hashes_MD5', 'hashes_SHA-256', 'hashes_SHA-512', 'name'], {
                      is: (a, b, c, d) => !a && !b && !c && !d,
                      then: () => Yup.string().matches(sha1Regex, t_i18n('SHA-1 values can only include A-F and 0-9, 40 characters')).required(t_i18n('MD5, SHA-1, SHA-256, SHA-512, or name is required')),
                    }),
                  'hashes_SHA-256': Yup
                    .string()
                    .when(['hashes_MD5', 'hashes_SHA-1', 'hashes_SHA-512', 'name'], {
                      is: (a, b, c, d) => !a && !b && !c && !d,
                      then: () => Yup.string().matches(sha256Regex, t_i18n('SHA-256 values can only include A-F and 0-9, 64 characters')).required(t_i18n('MD5, SHA-1, SHA-256, SHA-512, or name is required')),
                    }),
                  'hashes_SHA-512': Yup
                    .string()
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
                };

                requiredOneOfFields = [
                  ['hashes_MD5', 'hashes_SHA-1'],
                  ['hashes_MD5', 'hashes_SHA-256'],
                  ['hashes_MD5', 'hashes_SHA-512'],
                  ['hashes_MD5', 'name'],
                  // ['hashes_SHA-1', 'hashes_MD5'],
                  ['hashes_SHA-1', 'hashes_SHA-256'],
                  ['hashes_SHA-1', 'hashes_SHA-512'],
                  ['hashes_SHA-1', 'name'],
                  // ['hashes_SHA-256', 'hashes_MD5'],
                  // ['hashes_SHA-256', 'hashes_SHA-1'],
                  ['hashes_SHA-256', 'hashes_SHA-512'],
                  ['hashes_SHA-256', 'name'],
                  // ['hashes_SHA-512', 'hashes_MD5'],
                  // ['hashes_SHA-512', 'hashes_SHA-1'],
                  // ['hashes_SHA-512', 'hashes_SHA-256']
                  ['hashes_SHA-512', 'name'],
                ];
              } else if (attribute.value === 'value') {
                initialValues[attribute.value] = inputValue || '';
                // Dynamically include value field for Singular Observable type Object form validation
                const exceededMessage = t_i18n('You have exceeded the max number of values.');
                extraFieldsToValidate = {
                  [attribute.value]: Yup
                    .string()
                    .when(['bulk_value_field'], {
                      is: (a) => !a,
                      then: () => Yup.string().required(t_i18n('A value is required')),
                    }),
                  bulk_value_field: Yup
                    .string()
                    .when([attribute.value], {
                      is: (a) => !a,
                      then: () => Yup.string().required(t_i18n('Multiple value entry is required or Cancel this form')).test('len', exceededMessage, (val) => val.split('\n').length < 51),
                    }),
                };
                requiredOneOfFields = [
                  [attribute.value, 'bulk_value_field'],
                ];
              } else {
                initialValues[attribute.value] = '';
              }
            }
            const stixCyberObservableValidationBaseFields = {
              x_opencti_score: Yup.number().nullable(),
              x_opencti_description: Yup.string().nullable(),
              createIndicator: Yup.boolean(),
            };
            const stixCyberObservableValidationFinal = (extraRequiredFields = null) => Yup.object().shape({
              ...stixCyberObservableValidationBaseFields,
              ...extraRequiredFields,
            }, requiredOneOfFields);

            return (
              <Formik
                initialValues={initialValues}
                validationSchema={stixCyberObservableValidationFinal(extraFieldsToValidate)}
                onSubmit={onSubmit}
                onReset={onReset}
              >
                {({
                  submitForm,
                  handleReset,
                  isSubmitting,
                  setFieldValue,
                  isValid,
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
                                name="hashes_MD5"
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
                        if (attribute.value === 'value') {
                          return (
                            <div key={attribute.value}>
                              <Tooltip title="Copy/paste text content">
                                <BulkAdd
                                  setValue={(field_name, new_value) => setFieldValue(field_name, new_value)}
                                />
                              </Tooltip>

                              <Field
                                id="generic_value_field"
                                label="value" // For unit test to locate in tests_e2e/model/containerAddObservables.pageModel.ts
                                aria-labelledby="value" // For unit test to locate in tests_e2e/model/containerAddObservables.pageModel.ts
                                aria-label="value" // For unit test to locate in tests_e2e/model/containerAddObservables.pageModel.ts
                                disabled={genericValueFieldDisabled}
                                component={TextField}
                                variant="standard"
                                value={genericValueFieldValue}
                                key={attribute.value}
                                name={attribute.value}
                                fullWidth={true}
                                multiline={true}
                                rows="1"
                                onChange={(name, value) => setGenericValueFieldValue(value)}
                              />
                            </div>
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
                          />);
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
                      disabled={genericValueFieldDisabled}
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
                        disabled={isSubmitting && isValid}
                        onClick={() => { submitForm(); }}
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
      <>
        <Fab
          onClick={handleOpen}
          color="primary"
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
            <Typography variant="h6">{t_i18n('Create an observable')}</Typography>
          </div>
          <div className={classes.container}>
            {!status.type ? renderList() : renderForm()}
          </div>
        </Drawer>

        <ProgressDialogContainer
          openProgressDialog={openProgressDialog}
          bulkValueFieldValue={bulkValueFieldValue}
          handleClickCloseProgress={handleClickCloseProgress}
        />

      </>
    );
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
          PaperProps={{ elevation: 1 }}
          onClose={speeddial ? handleClose : localHandleClose}
          fullWidth={true}
        >
          <DialogTitle>{t_i18n('Create an observable')}</DialogTitle>
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

export default StixCyberObservableCreation;
