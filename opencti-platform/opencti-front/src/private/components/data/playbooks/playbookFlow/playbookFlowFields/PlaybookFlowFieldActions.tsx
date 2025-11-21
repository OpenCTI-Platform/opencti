import { v } from '@faker-js/faker/dist/airline-DF6RqYmq';
import { CancelOutlined, AddOutlined } from '@mui/icons-material';
import { IconButton, FormControl, InputLabel, MenuItem, Button, Alert, Grid } from '@mui/material';
import { Select } from 'formik-mui';
import { values } from 'ramda';
import R from 'types-ramda';
import { useState } from 'react';
import { capitalizeFirstLetter } from '../../../../../../utils/String';
import { useFormatter } from '../../../../../../components/i18n';
import { fieldSpacingContainerStyle } from '../../../../../../utils/field';

interface PlaybookFlowFieldActionsProps {
  actions: unknown[]
}

const PlaybookFlowFieldActions = ({
  actions,
}: PlaybookFlowFieldActionsProps) => {
  const { t_i18n } = useFormatter();
  const [actionsInputs, setActionsInputs] = useState(actions);

  return (
    <div
      className={classes.container}
      style={fieldSpacingContainerStyle}
    >
      {Array(actionsInputs.length)
        .fill(0)
        .map((_, i) => (
          <div key={i}>
            {(actionsInputs[i]?.op === 'replace' && ['objectMarking', 'objectLabel', 'objectAssignee', 'objectParticipant'].includes(actionsInputs[i]?.attribute)) && (
            <Alert severity="warning" style={{ marginBottom: 20 }}>
              {t_i18n('Replace operation will effectively replace this field values added in the context of this playbook such as enrichment or other knowledge manipulations but it will only append them if values are already written in the platform.')}
            </Alert>
            )}
            {(actionsInputs[i]?.op === 'replace' && actionsInputs[i]?.attribute === 'createdBy') && (
            <Alert severity="warning" style={{ marginBottom: 20 }}>
              {t_i18n('Replace operation will effectively replace the author if the confidence level of the entity with the new author is superior to the one of the entity with the old author.')}
            </Alert>
            )}
            {(actionsInputs[i]?.op === 'remove') && (
            <Alert severity="warning" style={{ marginBottom: 20 }}>
              {t_i18n('Remove operation will only apply on field values added in the context of this playbook such as enrichment or other knowledge manipulations but not if values are already written in the platform.')}
            </Alert>
            )}
            <div key={i} className={classes.step}>
              <IconButton
                disabled={actionsInputs.length === 1}
                aria-label="Delete"
                className={classes.stepCloseButton}
                onClick={() => {
                  handleRemoveStep(i);
                  setValues(
                    R.omit([`actions-${i}-value`], values),
                  );
                }}
                size="small"
              >
                <CancelOutlined fontSize="small" />
              </IconButton>
              <Grid container={true} spacing={3}>
                <Grid item xs={3}>
                  <FormControl className={classes.formControl}>
                    <InputLabel>{t_i18n('Action type')}</InputLabel>
                    <Select
                      variant="standard"
                      value={actionsInputs[i]?.op}
                      onChange={(event) => handleChangeActionInput(i, 'op', event.target.value)}
                    >
                      {(v.items?.properties?.op?.enum ?? ['add, replace, remove']).map((op) => (
                        <MenuItem key={op} value={op}>
                          {t_i18n(capitalizeFirstLetter(op))}
                        </MenuItem>
                      ))}
                    </Select>
                  </FormControl>
                </Grid>
                <Grid item xs={3}>
                  <FormControl className={classes.formControl}>
                    <InputLabel>{t_i18n('Field')}</InputLabel>
                    {renderFieldOptions(i, values, setValues)}
                  </FormControl>
                </Grid>
                <Grid item xs={6}>
                  {renderValuesOptions(i, setFieldValue)}
                </Grid>
              </Grid>
            </div>
          </div>
        ))}
      <div className={classes.add}>
        <Button
          disabled={!areStepsValid()}
          variant="contained"
          color="secondary"
          size="small"
          onClick={handleAddStep}
          classes={{ root: classes.buttonAdd }}
        >
          <AddOutlined fontSize="small" />
        </Button>
      </div>
    </div>
  );
};

export default PlaybookFlowFieldActions;
