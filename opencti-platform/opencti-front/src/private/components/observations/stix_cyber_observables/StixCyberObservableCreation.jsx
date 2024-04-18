import React, { useState } from 'react';
import { Field, Form, Formik } from 'formik';
import Drawer from '@mui/material/Drawer';
import Typography from '@mui/material/Typography';
import Button from '@mui/material/Button';
import IconButton from '@mui/material/IconButton';
import Fab from '@mui/material/Fab';
import { Add, Close, TextFieldsOutlined } from '@mui/icons-material';
import { assoc, compose, dissoc, filter, fromPairs, includes, map, pipe, pluck, prop, propOr, sortBy, toLower, toPairs } from 'ramda';
import * as Yup from 'yup';
import { graphql } from 'react-relay';
import DialogTitle from '@mui/material/DialogTitle';
import DialogContent from '@mui/material/DialogContent';
import DialogActions from '@mui/material/DialogActions';
import Tooltip from '@mui/material/Tooltip';
import Dialog from '@mui/material/Dialog';
import List from '@mui/material/List';
import ListItemText from '@mui/material/ListItemText';
import makeStyles from '@mui/styles/makeStyles';
import { ListItemButton } from '@mui/material';
import * as PropTypes from 'prop-types';
import { commitMutation, handleErrorInForm, QueryRenderer, MESSAGING$, commitMutationWithPromise } from '../../../../relay/environment';
import TextField from '../../../../components/TextField';
import SwitchField from '../../../../components/SwitchField';
import CreatedByField from '../../common/form/CreatedByField';
import ObjectLabelField from '../../common/form/ObjectLabelField';
import ObjectMarkingField from '../../common/form/ObjectMarkingField';
import { stixCyberObservablesLinesAttributesQuery, stixCyberObservablesLinesSubTypesQuery } from './StixCyberObservablesLines';
import { parse } from '../../../../utils/Time';
import MarkdownField from '../../../../components/MarkdownField';
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
  active_typography: {
    color: theme.palette.text.Typography,
  },
  disabled: {
    color: theme.palette.text.disabled,
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

const stixCyberObservableValidation = () => Yup.object().shape({
  x_opencti_score: Yup.number().nullable(),
  x_opencti_description: Yup.string().nullable(),
  createIndicator: Yup.boolean(),
});

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

  const handleOpen = () => setStatus({ open: true, type: status.type });
  const localHandleClose = () => setStatus({ open: false, type: type ?? null });
  const selectType = (selected) => setStatus({ open: status.open, type: selected });
  const [genericValueFieldDisabled, setGenericValueFieldDisabled] = useState(false);
  const [keyFieldDisabled, setKeyFieldDisabled] = useState(false);
  const bulkAddMsg = t_i18n('Multiple values entered. Edit with the TT button');
  const hashes_MD5_field = document.getElementById('hashes_MD5');
  const hashes_SHA1_field = document.getElementById('hashes_SHA-1');
  const hashes_SHA256_field = document.getElementById('hashes_SHA-256');
  const hashes_SHA512_field = document.getElementById('hashes_SHA-512');
  const divRowStyle = { display: 'flex', flexWrap: 'wrap' };
  const [myValue, setMyValue] = useState("");

  const onSubmit = (values, { setSubmitting, setErrors, resetForm }) => {
    console.log('onSubmit was called');
    let adaptedValues = values;
    if (adaptedValues) { // Verify not null for DeepScan compliance
      // Bulk Add Modal was used
      console.log("adaptedValues " + adaptedValues.value);
      console.log("adaptedValues.bulk_value_field " + adaptedValues.bulk_value_field);
      if (adaptedValues.value && adaptedValues.bulk_value_field && adaptedValues.value === bulkAddMsg) {
        console.log("inside bulk add, " + bulkAddMsg);
        const array_of_bulk_values = adaptedValues.bulk_value_field.split(/\r?\n/);
        // Trim them just to remove any extra spacing on front or rear of string
        const trimmed_bulk_values = array_of_bulk_values.map((s) => s.trim());
        // Remove any "" or empty resulting elements
        const cleaned_bulk_values = trimmed_bulk_values.reduce((elements, i) => (i ? [...elements, i] : elements), []);
        // De-duplicate by unique then rejoin
        adaptedValues.value = [...new Set(cleaned_bulk_values)].join('\n');
      }

      console.log("adaptedValues.hashes_SHA-256 " + adaptedValues['hashes_SHA-256']);
      // Potential dicts
      if (
        adaptedValues.hashes_MD5
        || adaptedValues['hashes_SHA-1']
        || adaptedValues['hashes_SHA-256']
        || adaptedValues['hashes_SHA-512']
      ) {
        console.log('inside potential dicts');
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

      const error_array = [];
      let validObservables = 0;
      const commit = async () => {
        const valueList = values?.value !== '' ? values?.value?.split('\n') || values?.value : undefined;
        if (valueList) {
          const promises = valueList.map((value) => commitMutationWithPromise({
            mutation: stixCyberObservableMutation,
            variables: {
              ...finalValues,
              [observableType]: { value },
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
          await Promise.allSettled(promises).then((results) => {
            results.forEach(({ status: promiseStatus, reason }) => {
              if (promiseStatus === 'fulfilled') {
                validObservables += 1;
              } else {
                error_array.push(reason);
              }
            });
          });
          const totalObservables = valueList.length;
          let closeFormWithAnySuccess = false;
          if (error_array.length > 0) {
            const errorObservables = error_array.length;
            let message_string = '';
            if (validObservables > 0) {
              message_string = `${validObservables}/${totalObservables} ${t_i18n('were added successfully.')}`;
              closeFormWithAnySuccess = true;
            }
            message_string += ` ${errorObservables}/${totalObservables} ${t_i18n('observables contained errors and were not added.')} `;
            const consolidated_errors = { res: { errors: error_array[0] } };
            // Short Error message, just has total success and failure counts with translation support
            consolidated_errors.res.errors[0].message = message_string;
            // Long Error message with all errors
            // consolidated_errors.res.errors[0].message = message_string + error_messages.join('\n');
            // Toast Error Message to Screen - Will not close the form since errors exist for correction.
            handleErrorInForm(consolidated_errors, setErrors);
          } else {
            let bulk_success_message = `${validObservables}/${totalObservables} ${t_i18n('were added successfully.')}`;
            if (totalObservables === 1) {
              // This is for consistent messaging when adding just (1) Observable
              bulk_success_message = t_i18n('Observable successfully added');
            }
            // Toast Message on Bulk Add Success
            MESSAGING$.notifySuccess(bulk_success_message);
            closeFormWithAnySuccess = true;
          }
          // Close the form if any observables were successfully added.
          if (closeFormWithAnySuccess === true) {
            localHandleClose();
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

  function BulkAddDialog(props) {
    // console.log('inside BulkAddDialog function');
    const [openBulkAddDialog, setOpenBulkAddDialog] = React.useState(false);
    const handleOpenBulkAddDialog = () => {
      if (hashes_MD5_field != null && hashes_MD5_field.value != null
        && hashes_MD5_field.value.length > 0 && hashes_MD5_field.value !== bulkAddMsg) {
        // Trim the field to avoid inserting whitespace as a default population value
        console.log('hashes_MD5_field');
        props.setValue('bulk_value_field', hashes_MD5_field.value.trim());
      }
      if (hashes_SHA1_field != null && hashes_SHA1_field.value != null
        && hashes_SHA1_field.value.length > 0 && hashes_SHA1_field.value !== bulkAddMsg) {
        // Trim the field to avoid inserting whitespace as a default population value
        console.log('hashes_SHA1_field');
        props.setValue('bulk_value_field', hashes_SHA1_field.value.trim());
      }
      if (hashes_SHA256_field != null && hashes_SHA256_field.value != null
        && hashes_SHA256_field.value.length > 0 && hashes_SHA256_field.value !== bulkAddMsg) {
        // Trim the field to avoid inserting whitespace as a default population value
        console.log('hashes_SHA256_field');
        props.setValue('bulk_value_field', hashes_SHA256_field.value.trim());
      }
      if (hashes_SHA512_field != null && hashes_SHA512_field.value != null
        && hashes_SHA512_field.value.length > 0 && hashes_SHA512_field.value !== bulkAddMsg) {
        // Trim the field to avoid inserting whitespace as a default population value
        console.log('hashes_SHA512_field');
        props.setValue('bulk_value_field', hashes_SHA512_field.value.trim());
      }
      setOpenBulkAddDialog(true);
    };
    const handleCloseBulkAddDialog = () => {
      setOpenBulkAddDialog(false);
      const bulk_value_field = document.getElementById('bulk_value_field');
      if (bulk_value_field != null && bulk_value_field.value != null && bulk_value_field.value.length > 0) {
        props.setValue('hashes', bulkAddMsg);
        setKeyFieldDisabled(true);
      } else {
        props.setValue('hashes', '');
        setKeyFieldDisabled(false);
      }
    };
    function getOption() {
      const selectElement = document.querySelector('#attributes');
      const output = selectElement.value;
      document.querySelector('.output').textContent = output;
    }
    return (
      <React.Fragment>
        <IconButton
          onClick={handleOpenBulkAddDialog}
          size="large"
          color="primary" style={{ float: 'left', marginRight: 25 }}
        >
          <TextFieldsOutlined />
        </IconButton>
        <Dialog
          PaperProps={{ elevation: 3 }}
          open={openBulkAddDialog}
          onClose={handleCloseBulkAddDialog}
          fullWidth={true}
        >
          <DialogContent style={{ marginTop: 0, paddingTop: 10 }}>
            <form name="formSelectAttributes" id="formSelectAttributes" style={{ border: '2px solid #FFA500', paddingLeft: 10 }} action="/action_page.php">
              {t_i18n('Create Entities from multiple')}:
              <select name="attributes" id="attributes" onSelect={getOption} onChange={(e) => setMyValue(e.target.value)}>
                <option selected disabled>Select attribute</option>
                <option value="NAME">name</option>
                <option value="MD5">md5</option>
                <option value="SHA1">sha1</option>
                <option value="SHA256">sha256</option>
                <option value="SHA512">sha512</option>
              </select>
            </form>
            <Typography style={{ float: 'left', marginTop: 10 }}>
              <span>{myValue}</span>
              <span className="output"></span>
            </Typography>
            <Field
              component={TextField}
              id="bulk_value_field"
              variant="standard"
              key="bulk_value_field"
              name="bulk_value_field"
              fullWidth={true}
              multiline={true}
              rows="5"
            />
            <DialogActions>
              <Button color="secondary" onClick={handleCloseBulkAddDialog}>
                {t_i18n('Validate')}
              </Button>
            </DialogActions>
          </DialogContent>
        </Dialog>
      </React.Fragment>
    );
  }

  BulkAddDialog.propTypes = {
    setValue: PropTypes.func,
  };

  function BulkAddModal(props) {
    console.log('inside bulkAddModal');
    const [openBulkModal, setOpenBulkModal] = React.useState(false);
    const handleOpenBulkModal = () => {
      const generic_value_field = document.getElementById('generic_value_field');
      if (generic_value_field != null && generic_value_field.value != null
        && generic_value_field.value.length > 0 && generic_value_field.value !== bulkAddMsg) {
        // Trim the field to avoid inserting whitespace as a default population value
        props.setValue('bulk_value_field', generic_value_field.value.trim());
      }
      setOpenBulkModal(true);
    };
    const handleCloseBulkModal = () => {
      setOpenBulkModal(false);
      const bulk_value_field = document.getElementById('bulk_value_field');
      if (bulk_value_field != null && bulk_value_field.value != null && bulk_value_field.value.length > 0) {
        props.setValue('value', bulkAddMsg);
        setGenericValueFieldDisabled(true);
      } else {
        props.setValue('value', '');
        setGenericValueFieldDisabled(false);
      }
    };
    const localHandleCancelClearBulkModal = () => {
      setOpenBulkModal(false);
      if (!genericValueFieldDisabled) {
        // If one-liner field isn't disabled, then you are it seems deciding
        // not to use the bulk add feature, so we will clear the field, since its population
        // is used to process the bul_value_field versus the generic_value_field
        props.setValue('bulk_value_field', '');
      }
      // else - you previously entered data and you just are canceling out of the popup window
      // but keeping your entry in the form.
    };
    return (
      <React.Fragment>
        <IconButton
          onClick={handleOpenBulkModal}
          size="large"
          color="primary" style={{ float: 'right', marginRight: 25 }}
        >
          <TextFieldsOutlined />
        </IconButton>
        <Dialog
          PaperProps={{ elevation: 3 }}
          open={openBulkModal}
          onClose={handleCloseBulkModal}
          fullWidth={true}
        >
          <DialogTitle>{t_i18n('Bulk Observable Creation')}</DialogTitle>
          <DialogContent style={{ marginTop: 0, paddingTop: 0 }}>
            <Typography id="add-bulk-observable-instructions" variant="subtitle1" component="subtitle1" style={{ whiteSpace: 'pre-line' }}>
              <div style={{ border: '2px solid #FFA500', paddingLeft: 10 }}>
                {t_i18n('Observables listed must be of the same type.')}
                <br />
                {t_i18n('One Observable per line.')}
              </div>
            </Typography>
            <Typography style={{ float: 'left', marginTop: 10 }}>
              {t_i18n('Bulk Content')}
            </Typography>
            <Field
              component={TextField}
              id="bulk_value_field"
              variant="standard"
              key="bulk_value_field"
              name="bulk_value_field"
              fullWidth={true}
              multiline={true}
              rows="5"
            />
            <DialogActions>
              <Button onClick={localHandleCancelClearBulkModal}>
                {t_i18n('Cancel')}
              </Button>
              <Button color="secondary" onClick={handleCloseBulkModal}>
                {t_i18n('Continue')}
              </Button>
            </DialogActions>
          </DialogContent>
        </Dialog>
      </React.Fragment>
    );
  }

  BulkAddModal.propTypes = {
    setValue: PropTypes.func,
  };

  const renderForm = () => {
    console.log("renderForm; status.type " + status.type);
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
              } else if (attribute.value === 'value') {
                initialValues[attribute.value] = inputValue || '';
              } else {
                initialValues[attribute.value] = '';
              }
            }
            return (
              <Formik
                initialValues={initialValues}
                validationSchema={stixCyberObservableValidation()}
                onSubmit={onSubmit}
                onReset={onReset}
              >
                {({
                  submitForm,
                  handleReset,
                  isSubmitting,
                  setFieldValue,
                  values,
                }) => (
                  <Form
                    style={{
                      margin: contextual ? '10px 0 0 0' : '20px 0 20px 0',
                    }}
                  >
                    <div style={(divRowStyle)}>
                      <p>{t_i18n('Create a single observable or multiple with ')}</p>
                      <Tooltip title="Copy/paste text content">
                        <BulkAddDialog
                          setValue={(field_name, new_value) => setFieldValue(field_name, new_value)}
                        />
                      </Tooltip>
                    </div>
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
                        if (attribute.value === 'hashes' && status.type === 'StixFile') {
                          return (
                            <div key={attribute.value}>
                              <Field
                                id="hashes_MD5"
                                disabled={keyFieldDisabled}
                                component={TextField}
                                variant="standard"
                                name="hashes_MD5"
                                label={t_i18n('hash_md5')}
                                fullWidth={true}
                                style={{ marginTop: 20 }}
                              />
                              <Field
                                id="hashes_SHA-1"
                                disabled={keyFieldDisabled}
                                component={TextField}
                                variant="standard"
                                name="hashes_SHA-1"
                                label={t_i18n('hash_sha-1')}
                                fullWidth={true}
                                style={{ marginTop: 20 }}
                              />
                              <Field
                                id="hashes_SHA-256"
                                disabled={keyFieldDisabled}
                                component={TextField}
                                variant="standard"
                                name="hashes_SHA-256"
                                label={t_i18n('hash_sha-256')}
                                fullWidth={true}
                                style={{ marginTop: 20 }}
                              />
                              <Field
                                id="hashes_SHA-512"
                                disabled={keyFieldDisabled}
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
                              <Typography className={genericValueFieldDisabled ? classes.disabled : classes.active_typography} style={{ float: 'left', marginTop: 20 }}>
                                {attribute.value}
                              </Typography>
                              <Tooltip title="Copy/paste text content">
                                <BulkAddModal
                                  setValue={(field_name, new_value) => setFieldValue(field_name, new_value)}
                                />
                              </Tooltip>

                              <Field
                                id="generic_value_field"
                                disabled={genericValueFieldDisabled}
                                component={TextField}
                                variant="standard"
                                key={attribute.value}
                                name={attribute.value}
                                label="generic_value_field"
                                fullWidth={true}
                                multiline={true}
                                rows="1"
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
                    <CustomFileUploader setFieldValue={setFieldValue} />
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
                        onClick={submitForm}
                        disabled={isSubmitting}
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
    if (status.type) {
      console.log("inside renderClassic");
      console.log("status.type " + status.type);
    }
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
