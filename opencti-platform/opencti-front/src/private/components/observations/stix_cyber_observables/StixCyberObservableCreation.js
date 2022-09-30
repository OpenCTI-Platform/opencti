import React, { Component } from 'react';
import * as PropTypes from 'prop-types';
import { Formik, Form, Field } from 'formik';
import withStyles from '@mui/styles/withStyles';
import Drawer from '@mui/material/Drawer';
import Typography from '@mui/material/Typography';
import Button from '@mui/material/Button';
import IconButton from '@mui/material/IconButton';
import Fab from '@mui/material/Fab';
import { Add, Close } from '@mui/icons-material';
import {
  compose,
  pluck,
  sortBy,
  toLower,
  prop,
  pipe,
  map,
  assoc,
  filter,
  includes,
  dissoc,
  toPairs,
  fromPairs,
  propOr,
} from 'ramda';
import * as Yup from 'yup';
import { graphql } from 'react-relay';
import { ConnectionHandler } from 'relay-runtime';
import DialogTitle from '@mui/material/DialogTitle';
import DialogContent from '@mui/material/DialogContent';
import Dialog from '@mui/material/Dialog';
import List from '@mui/material/List';
import ListItem from '@mui/material/ListItem';
import ListItemText from '@mui/material/ListItemText';
import inject18n from '../../../../components/i18n';
import {
  commitMutation,
  handleErrorInForm,
  QueryRenderer,
} from '../../../../relay/environment';
import TextField from '../../../../components/TextField';
import SwitchField from '../../../../components/SwitchField';
import CreatedByField from '../../common/form/CreatedByField';
import ObjectLabelField from '../../common/form/ObjectLabelField';
import ObjectMarkingField from '../../common/form/ObjectMarkingField';
import {
  stixCyberObservablesLinesAttributesQuery,
  stixCyberObservablesLinesSubTypesQuery,
} from './StixCyberObservablesLines';
import { parse } from '../../../../utils/Time';
import MarkDownField from '../../../../components/MarkDownField';
import ExternalReferencesField from '../../common/form/ExternalReferencesField';
import DateTimePickerField from '../../../../components/DateTimePickerField';

export const ignoredAttributes = [
  'internal_id',
  'standard_id',
  'x_opencti_description',
  'x_opencti_stix_ids',
  'entity_type',
  'spec_version',
  'extensions',
  'created',
  'modified',
  'created_at',
  'x_opencti_score',
  'updated_at',
  'observable_value',
  'indicators',
  'importFiles',
];

export const ignoredAttributesInFeeds = [
  'x_opencti_stix_ids',
  'spec_version',
  'extensions',
  'importFiles',
];

export const dateAttributes = [
  'ctime',
  'mtime',
  'atime',
  'attribute_date',
  'validity_not_before',
  'validity_not_after',
  'private_key_usage_period_not_before',
  'private_key_usage_period_not_after',
  'start',
  'end',
  'created_time',
  'modified_time',
  'account_created',
  'account_expires',
  'credential_last_changed',
  'account_first_login',
  'account_last_login',
  'expiration_date',
  'publication_date',
];

export const numberAttributes = [
  'number',
  'src_port',
  'dst_port',
  'src_byte_count',
  'dst_byte_count',
  'src_packets',
  'dst_packets',
  'pid',
  'size',
  'number_of_subkeys',
  'subject_public_key_exponent',
  'cvv',
];

export const booleanAttributes = [
  'is_self_signed',
  'is_multipart',
  'is_hidden',
  'is_active',
  'is_disabled',
  'is_privileged',
  'is_service_account',
  'can_escalate_privs',
];

export const multipleAttributes = ['x_opencti_additional_names', 'protocols'];

const styles = (theme) => ({
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
    right: 280,
    transition: theme.transitions.create('right', {
      easing: theme.transitions.easing.sharp,
      duration: theme.transitions.duration.enteringScreen,
    }),
  },
  createButtonExports: {
    position: 'fixed',
    bottom: 30,
    right: 590,
    transition: theme.transitions.create('right', {
      easing: theme.transitions.easing.easeOut,
      duration: theme.transitions.duration.leavingScreen,
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
  importButton: {
    position: 'absolute',
    top: 15,
    right: 20,
  },
  container: {
    padding: '10px 20px 20px 20px',
  },
  speedDialButton: {
    backgroundColor: theme.palette.secondary.main,
    color: '#ffffff',
    '&:hover': {
      backgroundColor: theme.palette.secondary.main,
    },
  },
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
        edges {
          node {
            id
            definition
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
`;

const stixCyberObservableValidation = (t) => Yup.object().shape({
  x_opencti_score: Yup.number().required(t('This field is required')),
  x_opencti_description: Yup.string().nullable(),
  createIndicator: Yup.boolean(),
});

const sharedUpdater = (
  store,
  userId,
  paginationKey,
  paginationOptions,
  newEdge,
) => {
  const userProxy = store.get(userId);
  const conn = ConnectionHandler.getConnection(
    userProxy,
    paginationKey,
    paginationOptions,
  );
  ConnectionHandler.insertEdgeBefore(conn, newEdge);
};

class StixCyberObservableCreation extends Component {
  constructor(props) {
    super(props);
    this.state = { open: false, type: props.type || null };
  }

  handleOpen() {
    this.setState({ open: true });
  }

  handleClose() {
    this.setState({ open: false, type: null });
  }

  selectType(type) {
    this.setState({ type });
  }

  onSubmit(values, { setSubmitting, setErrors, resetForm }) {
    let adaptedValues = values;
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
    const finalValues = {
      type: this.state.type,
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
      [this.state.type.replace(/(?:^|-|_)(\w)/g, (matches, letter) => letter.toUpperCase())]: adaptedValues,
    };
    commitMutation({
      mutation: stixCyberObservableMutation,
      variables: finalValues,
      updater: (store) => {
        const payload = store.getRootField('stixCyberObservableAdd');
        const newEdge = payload.setLinkedRecord(payload, 'node'); // Creation of the pagination container.
        const container = store.getRoot();
        sharedUpdater(
          store,
          container.getDataID(),
          this.props.paginationKey,
          this.props.paginationOptions,
          newEdge,
        );
      },
      onError: (error) => {
        handleErrorInForm(error, setErrors);
        setSubmitting(false);
      },
      setSubmitting,
      onCompleted: () => {
        setSubmitting(false);
        resetForm();
        this.handleClose();
      },
    });
  }

  onReset() {
    if (this.props.speeddial) {
      this.props.handleClose();
    } else {
      this.handleClose();
    }
  }

  renderList() {
    const { t } = this.props;
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
              map((n) => assoc('tlabel', t(`entity_${n.label}`), n)),
              sortByLabel,
            )(subTypesEdges);
            return (
              <List>
                {translatedOrderedList.map((subType) => (
                  <ListItem
                    key={subType.label}
                    divider={true}
                    button={true}
                    dense={true}
                    onClick={this.selectType.bind(this, subType.label)}
                  >
                    <ListItemText primary={subType.tlabel} />
                  </ListItem>
                ))}
              </List>
            );
          }
          return <div />;
        }}
      />
    );
  }

  renderForm(contextual = false) {
    const { type } = this.state;
    const { classes, t } = this.props;
    return (
      <QueryRenderer
        query={stixCyberObservablesLinesAttributesQuery}
        variables={{ elementType: type }}
        render={({ props }) => {
          if (props && props.schemaAttributes) {
            const initialValues = {
              x_opencti_description: '',
              x_opencti_score: 50,
              createdBy: '',
              objectMarking: [],
              objectLabel: [],
              externalReferences: [],
              createIndicator: false,
            };
            const attributes = pipe(
              map((n) => n.node),
              filter(
                (n) => !includes(n.value, ignoredAttributes)
                  && !n.value.startsWith('i_'),
              ),
            )(props.schemaAttributes.edges);
            for (const attribute of attributes) {
              if (includes(attribute.value, dateAttributes)) {
                initialValues[attribute.value] = null;
              } else if (includes(attribute.value, booleanAttributes)) {
                initialValues[attribute.value] = false;
              } else if (attribute.value === 'hashes') {
                initialValues.hashes_MD5 = '';
                initialValues['hashes_SHA-1'] = '';
                initialValues['hashes_SHA-256'] = '';
                initialValues['hashes_SHA-512'] = '';
              } else {
                initialValues[attribute.value] = '';
              }
            }
            return (
              <Formik
                initialValues={initialValues}
                validationSchema={stixCyberObservableValidation(t)}
                onSubmit={this.onSubmit.bind(this)}
                onReset={this.onReset.bind(this)}
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
                      margin: this.props.contextual
                        ? '10px 0 0 0'
                        : '20px 0 20px 0',
                    }}
                  >
                    <div>
                      <Field
                        component={TextField}
                        variant="standard"
                        name="x_opencti_score"
                        label={t('Score')}
                        fullWidth={true}
                        type="number"
                      />
                      <Field
                        component={MarkDownField}
                        name="x_opencti_description"
                        label={t('Description')}
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
                                label="hash_md5"
                                fullWidth={true}
                                style={{ marginTop: 20 }}
                              />
                              <Field
                                component={TextField}
                                variant="standard"
                                name="hashes_SHA-1"
                                label="hash_sha-1"
                                fullWidth={true}
                                style={{ marginTop: 20 }}
                              />
                              <Field
                                component={TextField}
                                variant="standard"
                                name="hashes_SHA-256"
                                label="hash_sha-256"
                                fullWidth={true}
                                style={{ marginTop: 20 }}
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
                              TextFieldProps={{
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
                              containerstyle={{ marginTop: 20 }}
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
                          />
                        );
                      })}
                    </div>
                    <CreatedByField
                      name="createdBy"
                      style={{ marginTop: 20, width: '100%' }}
                      setFieldValue={setFieldValue}
                    />
                    <ObjectLabelField
                      name="objectLabel"
                      style={{ marginTop: 20, width: '100%' }}
                      setFieldValue={setFieldValue}
                      values={values.objectLabel}
                    />
                    <ObjectMarkingField
                      name="objectMarking"
                      style={{ marginTop: 20, width: '100%' }}
                    />
                    <ExternalReferencesField
                      name="externalReferences"
                      style={{ marginTop: 20, width: '100%' }}
                      setFieldValue={setFieldValue}
                      values={values.externalReferences}
                    />
                    <Field
                      component={SwitchField}
                      type="checkbox"
                      name="createIndicator"
                      label={t('Create an indicator from this observable')}
                      containerstyle={{ marginTop: 20 }}
                    />
                    <div className={classes.buttons}>
                      <Button
                        variant={contextual ? 'text' : 'contained'}
                        onClick={handleReset}
                        disabled={isSubmitting}
                        classes={{ root: classes.button }}
                      >
                        {t('Cancel')}
                      </Button>
                      <Button
                        variant={contextual ? 'text' : 'contained'}
                        color="secondary"
                        onClick={submitForm}
                        disabled={isSubmitting}
                        classes={{ root: classes.button }}
                      >
                        {t('Create')}
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
  }

  renderClassic() {
    const { type } = this.state;
    const { t, classes, openExports } = this.props;
    return (
      <div>
        <Fab
          onClick={this.handleOpen.bind(this)}
          color="secondary"
          aria-label="Add"
          className={
            openExports ? classes.createButtonExports : classes.createButton
          }
        >
          <Add />
        </Fab>
        <Drawer
          open={this.state.open}
          anchor="right"
          sx={{ zIndex: 1202 }}
          elevation={1}
          classes={{ paper: classes.drawerPaper }}
          onClose={this.handleClose.bind(this)}
        >
          <div className={classes.header}>
            <IconButton
              aria-label="Close"
              className={classes.closeButton}
              onClick={this.handleClose.bind(this)}
              size="large"
              color="primary"
            >
              <Close fontSize="small" color="primary" />
            </IconButton>
            <Typography variant="h6">{t('Create an observable')}</Typography>
          </div>
          <div className={classes.container}>
            {!type ? this.renderList() : this.renderForm()}
          </div>
        </Drawer>
      </div>
    );
  }

  renderContextual() {
    const { type } = this.state;
    const { t, classes, display, speeddial } = this.props;
    return (
      <div style={{ display: display ? 'block' : 'none' }}>
        {!speeddial && (
          <Fab
            onClick={this.handleOpen.bind(this)}
            color="secondary"
            aria-label="Add"
            className={classes.createButtonContextual}
          >
            <Add />
          </Fab>
        )}
        <Dialog
          open={speeddial ? this.props.open : this.state.open}
          PaperProps={{ elevation: 1 }}
          onClose={
            speeddial
              ? this.props.handleClose.bind(this)
              : this.handleClose.bind(this)
          }
          fullWidth={true}
        >
          <DialogTitle>{t('Create an observable')}</DialogTitle>
          <DialogContent style={{ paddingTop: 0 }}>
            {!type ? this.renderList() : this.renderForm(true)}
          </DialogContent>
        </Dialog>
      </div>
    );
  }

  render() {
    const { contextual } = this.props;
    if (contextual) {
      return this.renderContextual();
    }
    return this.renderClassic();
  }
}

StixCyberObservableCreation.propTypes = {
  paginationKey: PropTypes.string,
  paginationOptions: PropTypes.object,
  classes: PropTypes.object,
  theme: PropTypes.object,
  t: PropTypes.func,
  contextual: PropTypes.bool,
  speeddial: PropTypes.bool,
  handleClose: PropTypes.func,
  open: PropTypes.bool,
  display: PropTypes.bool,
  inputValue: PropTypes.string,
  openExports: PropTypes.bool,
  type: PropTypes.string,
};

export default compose(
  inject18n,
  withStyles(styles, { withTheme: true }),
)(StixCyberObservableCreation);
