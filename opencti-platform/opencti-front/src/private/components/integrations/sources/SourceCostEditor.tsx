import React, { useState } from 'react';
import { graphql } from 'react-relay';
import { useIntl } from 'react-intl';
import { Field, Form, Formik } from 'formik';
import * as Yup from 'yup';
import { Stack, Typography } from '@mui/material';
import { EditOutlined } from '@mui/icons-material';
import Button from '@common/button/Button';
import Dialog from '@common/dialog/Dialog';
import FormButtonContainer from '@common/form/FormButtonContainer';
import TextField from '../../../../components/TextField';
import SelectFieldFds, { SelectItem } from '../../../../components/fields/SelectFieldFds';
import { useFormatter } from '../../../../components/i18n';
import useApiMutation from '../../../../utils/hooks/useApiMutation';
import { COST_PERIOD_LABELS, costCurrencyOptions, SOURCE_INTELLIGENCE_DOCUMENTATION_URL } from './sourceIntelligenceUtils';
import notifyMutationOutcome from './notifyMutationOutcome';
import { SourceCostEditorMutation, SourceCostPeriod } from './__generated__/SourceCostEditorMutation.graphql';

const sourceCostEditorMutation = graphql`
  mutation SourceCostEditorMutation($id: ID!, $input: SourceCostInput) {
    sourceSetCost(id: $id, input: $input) {
      id
      cost {
        amount
        currency
        period
      }
      latest_cost_per_actionable
    }
  }
`;

interface SourceCost {
  readonly amount: number;
  readonly currency: string;
  readonly period: string;
}

interface SourceCostEditorProps {
  sourceId: string;
  cost: SourceCost | null | undefined;
  primary?: boolean;
  initialOpen?: boolean;
}

interface CostFormValues {
  amount: string;
  currency: string;
  period: string;
}

const SourceCostEditor = ({ sourceId, cost, primary = false, initialOpen = false }: SourceCostEditorProps) => {
  const { t_i18n } = useFormatter();
  const intl = useIntl();
  const currencyLabel = (code: string) => {
    const name = intl.formatDisplayName(code, { type: 'currency', fallback: 'none' });
    return name ? `${code} - ${name}` : code;
  };
  const [open, setOpen] = useState(initialOpen);
  const [commit, inFlight] = useApiMutation<SourceCostEditorMutation>(sourceCostEditorMutation);
  const validation = Yup.object().shape({
    amount: Yup.number().typeError(t_i18n('This field must be a number')).required(t_i18n('This field is required')).min(0, t_i18n('The minimum is {min}', { values: { min: 0 } })),
    currency: Yup.string().required(t_i18n('This field is required')).matches(/^[A-Za-z]{3}$/, t_i18n('ISO 4217 currency code, for example EUR or USD')),
    period: Yup.string().required(t_i18n('This field is required')).oneOf(Object.keys(COST_PERIOD_LABELS)),
  });
  const initialValues: CostFormValues = {
    amount: cost ? String(cost.amount) : '',
    currency: cost?.currency ?? 'EUR',
    period: cost?.period ?? 'year',
  };
  const close = () => setOpen(false);
  const clearCost = () => commit({
    variables: { id: sourceId, input: null },
    onCompleted: (_, errors) => {
      if (notifyMutationOutcome(errors, { success: t_i18n('Source cost removed') })) close();
    },
  });

  return (
    <>
      <Button variant={primary ? undefined : 'secondary'} startIcon={<EditOutlined />} onClick={() => setOpen(true)} data-testid="source-cost-edit">
        {cost ? t_i18n('Edit the cost') : t_i18n('Set a cost')}
      </Button>
      <Dialog open={open} onClose={close} title={t_i18n('Cost of the source')} size="small">
        <Typography variant="body2" sx={{ marginBottom: 2 }}>
          {t_i18n('Costs are manual inputs used to compute the cost per actionable object. They are never shown as a financial return on investment.')}
        </Typography>
        <Formik<CostFormValues>
          initialValues={initialValues}
          validationSchema={validation}
          onSubmit={(values, { setSubmitting }) => {
            commit({
              variables: {
                id: sourceId,
                input: { amount: Number(values.amount), currency: values.currency.toUpperCase(), period: values.period as SourceCostPeriod },
              },
              onCompleted: (_, errors) => {
                setSubmitting(false);
                if (notifyMutationOutcome(errors, { success: t_i18n('Source cost saved') })) close();
              },
              onError: () => setSubmitting(false),
            });
          }}
        >
          {({ isSubmitting, submitForm }) => (
            <Form>
              <Stack gap={2}>
                <Field
                  component={TextField}
                  variant="standard"
                  type="number"
                  name="amount"
                  label={t_i18n('Amount')}
                  helperText={t_i18n('What the source costs over the period, for example 12000. It is required: to stop tracking the cost, use Remove the cost.')}
                  fullWidth
                  min={0}
                  step={0.01}
                />
                <Field
                  component={SelectFieldFds}
                  name="currency"
                  label={t_i18n('Currency')}
                  helpertext={t_i18n('The currency of the amount, for example USD; EUR when left unchanged. Costs are never converted: a cost widget only uses the sources of the currency most of them have.')}
                  fullWidth
                >
                  {costCurrencyOptions(cost?.currency).map((code) => (
                    <SelectItem key={code} value={code}>{currencyLabel(code)}</SelectItem>
                  ))}
                </Field>
                <Field
                  component={SelectFieldFds}
                  name="period"
                  label={t_i18n('Period')}
                  helpertext={t_i18n('What the amount pays for, for example a yearly subscription, the default. The cost is normalized to each scorecard window of 7, 30 and 90 days.')}
                  fullWidth
                >
                  {Object.entries(COST_PERIOD_LABELS).map(([value, label]) => (
                    <SelectItem key={value} value={value}>{t_i18n(label)}</SelectItem>
                  ))}
                </Field>
              </Stack>
              <FormButtonContainer>
                <Button variant="tertiary" component="a" href={`${SOURCE_INTELLIGENCE_DOCUMENTATION_URL}#cost`} target="_blank" rel="noopener noreferrer">
                  {t_i18n('Learn more')}
                </Button>
                {cost && (
                  <Button variant="secondary" intent="destructive" onClick={clearCost} disabled={isSubmitting || inFlight}>
                    {t_i18n('Remove the cost')}
                  </Button>
                )}
                <Button variant="secondary" onClick={close} disabled={isSubmitting}>{t_i18n('Cancel')}</Button>
                <Button onClick={submitForm} disabled={isSubmitting || inFlight} data-testid="source-cost-submit">{t_i18n('Save')}</Button>
              </FormButtonContainer>
            </Form>
          )}
        </Formik>
      </Dialog>
    </>
  );
};

export default SourceCostEditor;
