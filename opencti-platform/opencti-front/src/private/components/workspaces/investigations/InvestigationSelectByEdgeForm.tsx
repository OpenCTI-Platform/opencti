import Button from '@common/button/Button';
import DialogActions from '@mui/material/DialogActions';
import TextField from '@mui/material/TextField';
import Stack from '@mui/material/Stack';
import { Field, Form, Formik } from 'formik';
import { FormikHelpers } from 'formik/dist/types';
import { useMemo } from 'react';
import * as Yup from 'yup';
import CheckboxesField from '../../../../components/CheckboxesField';
import { GraphLink, GraphNode } from '../../../../components/graph/graph.types';
import { useFormatter } from '../../../../components/i18n';
import { FieldOption } from '../../../../utils/field';

export type SelectByEdgeFormData = {
  edge_count: number;
  entity_types: FieldOption[];
};

export type InvestigationSelectByEdgeFormProps = {
  nodes: GraphNode[];
  links: GraphLink[];
  onSubmit: (data: SelectByEdgeFormData, helpers: FormikHelpers<SelectByEdgeFormData>) => void;
  onReset: () => void;
};

const InvestigationSelectByEdgeForm = ({
  nodes,
  links: _links,
  onSubmit,
  onReset,
}: InvestigationSelectByEdgeFormProps) => {
  const { t_i18n } = useFormatter();

  const entityTypeOptions = useMemo<FieldOption[]>(() => {
    const types = new Set(nodes.map((n) => n.entity_type).filter(Boolean));
    return Array.from(types)
      .sort()
      .map((type) => ({ label: t_i18n(`entity_${type}`), value: type }));
  }, [nodes, t_i18n]);

  const validationSchema = Yup.object({
    edge_count: Yup.number()
      .min(0, t_i18n('Must be 0 or greater'))
      .integer(t_i18n('Must be a whole number'))
      .required(t_i18n('Required')),
  });

  return (
    <Formik<SelectByEdgeFormData>
      enableReinitialize={true}
      initialValues={{ edge_count: 0, entity_types: [] }}
      validationSchema={validationSchema}
      onSubmit={onSubmit}
      onReset={onReset}
    >
      {({ submitForm, handleReset, isSubmitting, values, handleChange, errors, touched }) => (
        <Form>
          <Stack spacing={3} sx={{ p: 3 }}>
            <TextField
              name="edge_count"
              label={t_i18n('Number of edges')}
              type="number"
              value={values.edge_count}
              onChange={handleChange}
              error={touched.edge_count && Boolean(errors.edge_count)}
              helperText={touched.edge_count && errors.edge_count}
              inputProps={{ min: 0 }}
              fullWidth
            />

            <Field
              name="entity_types"
              component={CheckboxesField}
              label={t_i18n('All types of node')}
              items={entityTypeOptions}
            />

            <DialogActions>
              <Button variant="secondary" onClick={handleReset} disabled={isSubmitting}>
                {t_i18n('Cancel')}
              </Button>
              <Button onClick={submitForm} disabled={isSubmitting}>
                {t_i18n('Select')}
              </Button>
            </DialogActions>
          </Stack>
        </Form>
      )}
    </Formik>
  );
};

export default InvestigationSelectByEdgeForm;
