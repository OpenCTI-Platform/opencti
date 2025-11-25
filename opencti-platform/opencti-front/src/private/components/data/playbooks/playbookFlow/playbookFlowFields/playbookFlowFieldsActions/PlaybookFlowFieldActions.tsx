import { CancelOutlined, AddOutlined } from '@mui/icons-material';
import { IconButton, MenuItem, Button, Grid2 as Grid } from '@mui/material';
import { Field, FieldArray, useFormikContext } from 'formik';
import { useTheme } from '@mui/styles';
import { capitalizeFirstLetter } from '../../../../../../../utils/String';
import { useFormatter } from '../../../../../../../components/i18n';
import { fieldSpacingContainerStyle } from '../../../../../../../utils/field';
import { isEmptyField } from '../../../../../../../utils/utils';
import type { Theme } from '../../../../../../../components/Theme';
import SelectField from '../../../../../../../components/fields/SelectField';
import { PlaybookUpdateActionsForm } from './playbookAction-types';
import PlaybookActionAlerts from './PlaybookActionAlerts';
import useActionFieldOptions from './useActionFieldOptions';
import PlaybookActionValueField from './PlaybookActionValueField';

interface PlaybookFlowFieldActionsProps {
  operations?: string[]
}

const PlaybookFlowFieldActions = ({
  operations = ['add, replace, remove'],
}: PlaybookFlowFieldActionsProps) => {
  const theme = useTheme<Theme>();
  const { t_i18n } = useFormatter();
  const getActionFieldOptions = useActionFieldOptions();
  const { values } = useFormikContext<PlaybookUpdateActionsForm>();

  const actionsAreValid = values.actions.every((a) => {
    if (a.attribute === 'x_opencti_detection') return true;
    return a.op && a.attribute && a.value && a.value.length > 0;
  });

  return (
    <FieldArray
      name="actions"
      render={(arrayHelpers) => (
        <div style={fieldSpacingContainerStyle}>
          {values.actions.map((action, i) => {
            const fieldOptions = getActionFieldOptions(action);

            return (
              <div key={i}>
                <PlaybookActionAlerts action={action} />
                <div style={{
                  position: 'relative',
                  width: '100%',
                  margin: '0 0 20px 0',
                  padding: '15px',
                  verticalAlign: 'middle',
                  border: `1px solid ${theme.palette.primary.main}`,
                  borderRadius: 4,
                  display: 'flex',
                }}
                >
                  <IconButton
                    size="small"
                    aria-label="Delete"
                    disabled={values.actions.length === 1}
                    onClick={() => arrayHelpers.remove(i)}
                    sx={{
                      position: 'absolute',
                      top: -18,
                      right: -18,
                    }}
                  >
                    <CancelOutlined fontSize="small" />
                  </IconButton>
                  <Grid container spacing={3} sx={{ width: '100%' }}>
                    <Grid size={{ xs: 3 }}>
                      <Field
                        component={SelectField}
                        variant="standard"
                        name={`actions.${i}.op`}
                        containerstyle={{ width: '100%' }}
                        label={t_i18n('Action type')}
                      >
                        {operations.map((op) => (
                          <MenuItem key={op} value={op}>
                            {t_i18n(capitalizeFirstLetter(op))}
                          </MenuItem>
                        ))}
                      </Field>
                    </Grid>
                    <Grid size={{ xs: 3 }}>
                      <Field
                        component={SelectField}
                        disabled={isEmptyField(action.op)}
                        variant="standard"
                        name={`actions.${i}.attribute`}
                        containerstyle={{ width: '100%' }}
                        label={t_i18n('Field')}
                      >
                        {fieldOptions.length === 0
                          ? <MenuItem value="none">{t_i18n('None')}</MenuItem>
                          : fieldOptions.map((option) => (
                            <MenuItem key={option.value} value={option.value}>
                              {option.label}
                            </MenuItem>
                          ))
                        }
                      </Field>
                    </Grid>
                    <Grid size={{ xs: 6 }}>
                      <PlaybookActionValueField
                        action={action}
                        index={i}
                      />
                    </Grid>
                  </Grid>
                </div>
              </div>
            );
          })}
          <Button
            size="small"
            color="secondary"
            variant="contained"
            onClick={() => arrayHelpers.push({})}
            disabled={!actionsAreValid}
            style={{ width: '100%', height: 20 }}
          >
            <AddOutlined fontSize="small" />
          </Button>
        </div>
      )}
    />
  );
};

export default PlaybookFlowFieldActions;
