import { makeStyles } from '@mui/styles';
import { FunctionComponent, useState } from 'react';
import { graphql, useMutation } from 'react-relay';
import { RecordSourceSelectorProxy } from 'relay-runtime';
import * as Yup from 'yup';
import * as R from 'ramda';
import { Field, Form, Formik, FormikConfig } from 'formik';
import { Button, Drawer, Fab, IconButton, Typography } from '@mui/material';
import { Add } from '@mui/icons-material';
import { Close } from 'mdi-material-ui';
import { Theme } from '../../../../components/Theme';
import { Option } from '../../common/form/ReferenceField';
import { useFormatter } from '../../../../components/i18n';
import TextField from '../../../../components/TextField';
import CreatedByField from '../../common/form/CreatedByField';
import ObjectLabelField from '../../common/form/ObjectLabelField';
import { fieldSpacingContainerStyle } from '../../../../utils/field';
import ObjectMarkingField from '../../common/form/ObjectMarkingField';
import { ExternalReferencesField } from '../../common/form/ExternalReferencesField';
import { insertNode } from '../../../../utils/store';
import AutocompleteField from '../../../../components/AutocompleteField';
import { AssetLinesPaginationQuery$variables } from './__generated__/AssetLinesPaginationQuery.graphql';
import { CurrencyCode, displayCurrencyCode } from '../accounts/AccountCreation';
import { valToKey } from '../../../../utils/Localization';

export enum FinancialAssetType {
  airplane = 'Airplane',
  boat = 'Boat',
  car = 'Car',
  company = 'Company',
  domain_name = 'Domain name',
  real_estate = 'Real estate',
  digital = 'Digital',
  other = 'Other',
}

const useStyles = makeStyles<Theme>((theme) => ({
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

const assetMutation = graphql`
  mutation AssetCreationMutation($input: FinancialAssetAddInput!) {
    financialAssetAdd(input: $input) {
      id
      name
      entity_type
      ...AssetLine_node
    }
  }
`;

interface AssetAddInput {
  name: string
  asset_type: string
  asset_value: number
  currency_code: CurrencyCode
  createdBy: Option | undefined
  objectMarking: Option[]
  objectLabel: Option[]
  externalReferences: Option[]
}

interface AssetFormProps {
  updater: (store: RecordSourceSelectorProxy, key: string) => void
  onReset?: () => void
  onCompleted?: () => void
  defaultCreatedBy?: Option
  defaultMarkingDefinitions?: Option[]
}

export const assetShape = (t: (message: string) => string) => ({
  name: Yup.string()
    .min(2, 'Asset name must be at least 2 characters')
    .required(t('This field is required')),
  asset_type: Yup.mixed<string>()
    .oneOf(Object.keys(FinancialAssetType)),
  asset_value: Yup.number().integer('Asset value must be an integer')
    .min(0, 'Asset value cannot be a negative number'),
  currency_code: Yup.mixed<CurrencyCode>()
    .oneOf(Object.values(CurrencyCode)),
  createdBy: Yup.object().nullable(),
  objectMarking: Yup.array().nullable(),
});

export function getAssetSchema(t: (message: string) => string) {
  return Yup.object().shape(assetShape(t));
}

export const AssetCreationForm: FunctionComponent<AssetFormProps> = ({ updater, onReset, onCompleted, defaultCreatedBy, defaultMarkingDefinitions }) => {
  const classes = useStyles();
  const { t } = useFormatter();
  const assetSchema = getAssetSchema(t);
  const [commit] = useMutation(assetMutation);

  const onSubmit: FormikConfig<AssetAddInput>['onSubmit'] = (values, { setSubmitting, resetForm }) => {
    const finalValues = R.pipe(
      R.assoc('currency_code', values.currency_code),
      R.assoc('name', values.name),
      R.assoc('asset_type', values.asset_type),
      R.assoc('asset_value', Number(values.asset_value)),
      R.assoc('createdBy', values.createdBy?.value),
      R.assoc('objectMarking', R.pluck('value', values.objectMarking)),
      R.assoc('objectLabel', R.pluck('value', values.objectLabel)),
      R.assoc('externalReferences', R.pluck('value', values.externalReferences)),
    )(values);
    commit({
      variables: {
        input: finalValues,
      },
      updater: (store) => {
        if (updater) {
          updater(store, 'financialAssetAdd');
        }
      },
      onCompleted: () => {
        setSubmitting(false);
        resetForm();
        if (onCompleted) {
          onCompleted();
        }
      },
    });
  };
  return <Formik<AssetAddInput>
    initialValues={{
      name: '',
      asset_type: Object.keys(FinancialAssetType)[0],
      asset_value: 0,
      currency_code: CurrencyCode.united_states_dollar__usd,
      createdBy: defaultCreatedBy ?? undefined,
      objectMarking: defaultMarkingDefinitions ?? [],
      objectLabel: [],
      externalReferences: [],
    }}
    validationSchema={assetSchema}
    onSubmit={onSubmit}
    onReset={onReset}>
    {({
      submitForm,
      handleReset,
      isSubmitting,
      setFieldValue,
      values,
    }) => (
      <Form style={{ margin: '20px 0 20px 0' }}>
        <Field
          component={TextField}
          variant="standard"
          name="name"
          label={t('Asset Name')}
          fullWidth={true}
          detectDuplicate={['Financial-Asset']}
        />
        <Field
          component={AutocompleteField}
          name={'asset_type'}
          multiple={false}
          style={{ margin: '20px 0 20px 0' }}
          textfieldprops={{
            variant: 'standard',
            label: t('Asset Type'),
          }}
          noOptionsText={t('No available options')}
          options={Object.entries(FinancialAssetType)}
          value={t(valToKey(values?.asset_type, FinancialAssetType))}
          renderOption={(props: React.HTMLAttributes<HTMLLIElement>, [_, value]: [string, string]) => (
            <li {...props}> {t(value)} </li>
          )}
          onChange={(field: string, [key]: [string]) => setFieldValue(field, key) }
        />
        <Field
          component={TextField}
          variant="standard"
          name="asset_value"
          style={{ margin: '20px 0 20px 0' }}
          label={t('Asset Value')}
          fullWidth={true}
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
          value={displayCurrencyCode(values?.currency_code || t('Unknown'))}
          renderOption={(props: React.HTMLAttributes<HTMLLIElement>, option: string) => (
            <li {...props}> {displayCurrencyCode(option)} </li>
          )}
        />
        <CreatedByField
          name="createdBy"
          style={{
            marginTop: 20,
            width: '100%',
          }}
          setFieldValue={setFieldValue}
        />
        <ObjectLabelField
          name="objectLabel"
          style={fieldSpacingContainerStyle}
          setFieldValue={setFieldValue}
          values={values?.objectLabel}
        />
        <ObjectMarkingField
          name="objectMarking"
          style={{
            marginTop: 20,
            width: '100%',
          }}
        />
        <ExternalReferencesField
          name="externalReferences"
          style={fieldSpacingContainerStyle}
          setFieldValue={setFieldValue}
          values={values?.externalReferences}
        />
        <div className={classes.buttons}>
          <Button
            variant="contained"
            onClick={handleReset}
            disabled={isSubmitting}
            classes={{ root: classes.button }}
          >
            {t('Cancel')}
          </Button>
          <Button
            variant="contained"
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
  </Formik>;
};

const AssetCreation = ({ paginationOptions }: { paginationOptions: AssetLinesPaginationQuery$variables }) => {
  const { t } = useFormatter();
  const classes = useStyles();

  const [open, setOpen] = useState<boolean>(false);
  const handleOpen = () => setOpen(true);
  const handleClose = () => setOpen(false);
  const updater = (store: RecordSourceSelectorProxy) => insertNode(
    store,
    'Pagination_financialAssets',
    paginationOptions,
    'financialAssetAdd',
  );

  return (
    <div>
      <Fab onClick={handleOpen}
        color="secondary"
        aria-label="Add"
        className={classes.createButton}>
        <Add />
      </Fab>
      <Drawer open={open}
        anchor="right"
        elevation={1}
        sx={{ zIndex: 1202 }}
        classes={{ paper: classes.drawerPaper }}
        onClose={handleClose}>
        <div className={classes.header}>
          <IconButton aria-label="Close"
            className={classes.closeButton}
            onClick={handleClose}
            size="large"
            color="primary">
            <Close fontSize="small" color="primary" />
          </IconButton>
          <Typography variant="h6">{t('Create a financial asset')}</Typography>
        </div>
        <div className={classes.container}>
          <AssetCreationForm updater={updater} onCompleted={handleClose} onReset={handleClose} />
        </div>
      </Drawer>
    </div>
  );
};

export default AssetCreation;
