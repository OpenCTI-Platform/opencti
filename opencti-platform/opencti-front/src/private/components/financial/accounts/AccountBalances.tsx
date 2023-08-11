import * as Yup from 'yup';
import { Field, Form, Formik, FormikConfig } from 'formik';
import React, { FunctionComponent, useState } from 'react';
import {
  DataGrid,
  GRID_DATE_COL_DEF,
  GridColDef,
  GridFooter,
  GridRenderEditCellParams,
  GridValueFormatterParams,
  useGridApiContext,
} from '@mui/x-data-grid';
import { v4 as uuidv4 } from 'uuid';
import { graphql } from 'relay-runtime';
import { makeStyles } from '@mui/styles';
import { useMutation } from 'react-relay';
import { Grid, Box, Stack, Alert, Button, TextField as MuiTextField } from '@mui/material';
import { DatePicker, LocalizationProvider } from '@mui/x-date-pickers';
import { AdapterDateFns } from '@mui/x-date-pickers/AdapterDateFns';
import { useFormatter } from '../../../../components/i18n';
import { Account_financialAccount$data } from './__generated__/Account_financialAccount.graphql';
import Security from '../../../../utils/Security';
import useGranted, { KNOWLEDGE_KNUPDATE } from '../../../../utils/hooks/useGranted';
import { Theme } from '../../../../components/Theme';
import TextField from '../../../../components/TextField';
import DatePickerField from '../../../../components/DatePickerField';

const useStyles = makeStyles<Theme>(() => ({
  buttons: {
    float: 'right',
  },
  button: {
    margin: 5,
  },
}));

const balanceMutation = graphql`
  mutation AccountBalancesMutation(
    $id: ID!
    $input: [EditInput]!
  ){
    financialAccountFieldPatch(id: $id, input: $input) {
      financial_account_balances {
        as_of_date
        balance
      }
    }
  }
`;

interface BalanceInputsProps {
  id: string
  setFormVisible:(value :boolean) => void
}

interface FinancialAccountBalance {
  id?: string,
  as_of_date: Date | null
  balance: number | null
}

const BalanceUpdateForm: FunctionComponent<BalanceInputsProps> = ({ id, setFormVisible }) => {
  const classes = useStyles();
  const { t } = useFormatter();

  const basicShape = {
    as_of_date: Yup.date()
      .typeError(t('The value must be a date (yyyy-MM-dd)')),
    balance: Yup.number()
      .required()
      .min(0)
      .typeError(t('The value must be a positive number')),
  };

  const accountValidator = Yup.object().shape(basicShape);
  const [commit] = useMutation(balanceMutation);
  const [isFormVisible] = useState(true);

  const onSubmit: FormikConfig<FinancialAccountBalance>['onSubmit'] = (values, { setSubmitting, resetForm }) => {
    const newBalance: FinancialAccountBalance = {
      as_of_date: values.as_of_date,
      balance: Number(values.balance),
    };
    commit({
      variables: {
        id,
        input: {
          key: 'financial_account_balances',
          value: [newBalance],
          operation: 'add',
        },
      },
      onCompleted: () => {
        setSubmitting(false);
        resetForm();
        setFormVisible(false);
      },
    });
  };

  return (
    <div>
      {isFormVisible && (
        <Formik<FinancialAccountBalance>
          initialValues={{
            as_of_date: null,
            balance: null,
          }}
          validationSchema={accountValidator}
          onSubmit={onSubmit}
        >
          {({
            submitForm,
            handleReset,
            isSubmitting,
          }) => (
            <Form style={{ margin: '20px 0 20px 0' }}>
              <Field
                component={DatePickerField}
                name='as_of_date'
                TextFieldProps={{
                  label: t('As of Date'),
                  variant: 'standard',
                  fullWidth: true,
                }}
              />
              <Field
                component={TextField}
                variant='standard'
                name='balance'
                label={t('Balance')}
                fullWidth={true}
              />
              <div className={classes.buttons}>
                <Button
                  variant='contained'
                  color='secondary'
                  onClick={() => {
                    handleReset();
                    setFormVisible(false);
                  }}
                  disabled={isSubmitting}
                  classes={{ root: classes.button }}
                >
                  {t('Cancel')}
                </Button>
                <Button
                  variant='contained'
                  onClick={() => {
                    submitForm();
                    setFormVisible(false);
                  }}
                  disabled={isSubmitting}
                  classes={{ root: classes.button }}
                >
                  {t('Create')}
                </Button>
              </div>
            </Form>
          )}
        </Formik>
      )}
    </div>
  );
};

interface AccountBalancesProps {
  account: Account_financialAccount$data
  isEditable: boolean
}

const AccountBalances = ({
  account,
  isEditable = false,
}: AccountBalancesProps) => {
  // Editable Date Cell Sub-Component
  const GridEditDateCell = ({ id, field, value }: GridRenderEditCellParams) => {
    const apiRef = useGridApiContext();
    function handleChange(newValue: GridRenderEditCellParams['value']) {
      apiRef.current.setEditCellValue({ id, field, value: newValue });
    }
    return (
      <DatePicker
        value={value}
        renderInput={(params) => {
          return (<MuiTextField {...params} />);
        }}
        onChange={handleChange}
      />
    );
  };

  // Member Variables
  const { t, fd, fm } = useFormatter();
  const [showAddBalanceForm, setShowAddBalanceForm] = useState(false);
  const [commit] = useMutation(balanceMutation);

  const rows: FinancialAccountBalance[] = account.financial_account_balances?.map((balanceEntry) => ({
    id: uuidv4(),
    as_of_date: balanceEntry?.as_of_date ? new Date(balanceEntry?.as_of_date) : new Date(),
    balance: balanceEntry?.balance ?? 0,
  })) ?? [];
  const dateColumnType = {
    ...GRID_DATE_COL_DEF,
  };
  const columns: GridColDef[] = [
    {
      ...dateColumnType,
      field: 'as_of_date',
      headerName: t('As of Date'),
      type: 'date',
      resizable: false,
      editable: isEditable && useGranted([KNOWLEDGE_KNUPDATE]),
      flex: 1,
      valueFormatter: (params: GridValueFormatterParams<string | number | Date | undefined>) => fd(params?.value) || params?.value,
      renderEditCell: (params: GridRenderEditCellParams) => <GridEditDateCell {...params} />,
    },
    {
      field: 'balance',
      headerName: t('Balance'),
      sortable: false,
      valueFormatter: (params: GridValueFormatterParams<number | bigint>) => fm(params?.value, account.currency_code?.toString()) || t('Unknown'),
      editable: isEditable && useGranted([KNOWLEDGE_KNUPDATE]),
      flex: 1,
    },
  ];

  // Event Handlers
  const handleAddBalance = () => {
    setShowAddBalanceForm(true);
  };
  const handleHideField = (value: boolean) => {
    setShowAddBalanceForm(value);
  };
  const handleProcessRowUpdate = (
    newRow: FinancialAccountBalance,
    oldRow: FinancialAccountBalance,
  ) => {
    const balanceToNumber = Number(newRow.balance);
    if (Number.isNaN(balanceToNumber)) { return oldRow; }
    const formattedRow = { ...newRow, balance: balanceToNumber };
    const newAccountBalances: FinancialAccountBalance[] = rows.map((row) => (row.id === formattedRow.id ? formattedRow : row));
    commit({
      variables: {
        id: account.id,
        input: [{
          key: 'financial_account_balances',
          value: newAccountBalances.map(b => ({ as_of_date: b.as_of_date, balance: b.balance })),
          operation: 'replace',
        }]
      }
    })
    return formattedRow;
  };

  // Footer Sub-Component
  const footer = () => {
    const apiRef = useGridApiContext();
    const handleDeleteRows = () => {
      const selectedRows = apiRef.current.getSelectedRows();
      const remainingRows = rows.filter(
        (balance) => !selectedRows.get(balance?.id || ''),
      );
      commit({
        variables: {
          id: account.id,
          input: [{
            key: 'financial_account_balances',
            value: remainingRows.map(b => ({ as_of_date: b.as_of_date, balance: b.balance })),
            operation: 'replace',
          }]
        }
      });
    };
    return (
      <React.Fragment>
        <GridFooter />
          {apiRef.current.getSelectedRows().size > 0 && <Alert
            severity="error"
            variant="outlined"
            action={
              <Button color="inherit" size="small" onClick={handleDeleteRows}>
                DELETE
              </Button>
            }
          >
            {'Delete rows?'}
          </Alert>}
      </React.Fragment>
    );
  };

  // Component Definition
  return (
    <Stack spacing={2} sx={{ width: '100%' }}>
      <Box sx={{ width: '100%' }}>
        <LocalizationProvider dateAdapter={AdapterDateFns}>
          <DataGrid
            rows={rows}
            columns={columns}
            initialState={{
              pagination: {
                paginationModel: {
                  pageSize: 5,
                },
              },
            }}
            pageSizeOptions={[5]}
            autoHeight={true}
            checkboxSelection={true}
            disableRowSelectionOnClick={true}
            slots={{ footer }}
            processRowUpdate={handleProcessRowUpdate}
            editMode="row"
          />
          {isEditable
            && <Security needs={[KNOWLEDGE_KNUPDATE]}>
              <Grid item={true} xs={12}>
                {!showAddBalanceForm
                  && <Button onClick={handleAddBalance} color='primary' style={{ float: 'right' }}>
                    {t('Add Balance')}
                  </Button>
                }
                {showAddBalanceForm
                  && <div>
                    <BalanceUpdateForm
                      id={account.id}
                      setFormVisible={handleHideField}
                    />
                  </div>
                }
              </Grid>
            </Security>
          }
        </LocalizationProvider>
      </Box>
    </Stack>
  );
};

export default AccountBalances;
