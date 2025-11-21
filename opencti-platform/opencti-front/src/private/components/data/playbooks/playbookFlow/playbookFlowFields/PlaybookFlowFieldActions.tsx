import { CancelOutlined, AddOutlined } from '@mui/icons-material';
import { IconButton, FormControl, InputLabel, MenuItem, Button, Alert, Grid, Select } from '@mui/material';
import { values } from 'ramda';
import { useState } from 'react';
import { capitalizeFirstLetter } from '../../../../../../utils/String';
import { useFormatter } from '../../../../../../components/i18n';
import { fieldSpacingContainerStyle } from '../../../../../../utils/field';

interface UpdateAction {
  op?: string
  attribute?: string
  value?: {
    label?: string
    value?: string
    patch_value?: string
  }[]
}

interface ActionAlertsProps {
  action: UpdateAction
}

const ActionAlerts = ({ action }: ActionAlertsProps) => {
  const { t_i18n } = useFormatter();

  return (
    <>
      {(action.op === 'replace' && ['objectMarking', 'objectLabel', 'objectAssignee', 'objectParticipant'].includes(action.attribute ?? '')) && (
        <Alert severity="warning" style={{ marginBottom: 20 }}>
          {t_i18n('Replace operation will effectively replace this field values added in the context of this playbook such as enrichment or other knowledge manipulations but it will only append them if values are already written in the platform.')}
        </Alert>
      )}
      {(action.op === 'replace' && action.attribute === 'createdBy') && (
        <Alert severity="warning" style={{ marginBottom: 20 }}>
          {t_i18n('Replace operation will effectively replace the author if the confidence level of the entity with the new author is superior to the one of the entity with the old author.')}
        </Alert>
      )}
      {(action.op === 'remove') && (
        <Alert severity="warning" style={{ marginBottom: 20 }}>
          {t_i18n('Remove operation will only apply on field values added in the context of this playbook such as enrichment or other knowledge manipulations but not if values are already written in the platform.')}
        </Alert>
      )}
    </>
  );
};

interface PlaybookFlowFieldActionsProps {
  actions: UpdateAction[]
  operations?: string[]
}

const PlaybookFlowFieldActions = ({
  actions,
  operations = ['add, replace, remove'],
}: PlaybookFlowFieldActionsProps) => {
  const { t_i18n } = useFormatter();
  const [actionsInputs, setActionsInputs] = useState(actions);

  const addAction = () => {
    setActionsInputs((inputs) => [...inputs, {}]);
  };

  const removeAction = (index: number) => {
    setActionsInputs((inputs) => inputs.splice(index, 1));
  };

  const changeAction = (index: number, action: UpdateAction) => {
    setActionsInputs((inputs) => (
      inputs.map((input, i) => {
        if (index === i) return action;
        return input;
      })
    ));
  };

  const changeOp = (index: number, op: UpdateAction['op']) => {
    const action = actionsInputs[index];
    changeAction(index, { ...action, op });
  };

  const changeAttribute = (index: number, attribute: UpdateAction['attribute']) => {
    const action = actionsInputs[index];
    changeAction(index, { ...action, attribute });
  };

  const changeValue = (index: number, value: UpdateAction['value']) => {
    const action = actionsInputs[index];
    changeAction(index, { ...action, value });
  };

  const actionsAreValid = actionsInputs.every((a) => {
    if (a.attribute === 'x_opencti_detection') return true;
    return a.op && a.attribute && a.value && a.value.length > 0;
  });

  return (
    <div
      className={classes.container}
      style={fieldSpacingContainerStyle}
    >
      {actionsInputs.map((action, i) => (
        <div key={i}>
          <ActionAlerts action={action} />
          <div className={classes.step}>
            <IconButton
              size="small"
              aria-label="Delete"
              className={classes.stepCloseButton}
              disabled={actionsInputs.length === 1}
              onClick={() => removeAction(i)}
            >
              <CancelOutlined fontSize="small" />
            </IconButton>
            <Grid container={true} spacing={3}>
              <Grid item xs={3}>
                <FormControl className={classes.formControl}>
                  <InputLabel>{t_i18n('Action type')}</InputLabel>
                  <Select
                    variant="standard"
                    value={action.op}
                    onChange={(event) => changeOp(i, event.target.value)}
                  >
                    {operations.map((op) => (
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
          disabled={actionsAreValid}
          variant="contained"
          color="secondary"
          size="small"
          onClick={addAction}
          classes={{ root: classes.buttonAdd }}
        >
          <AddOutlined fontSize="small" />
        </Button>
      </div>
    </div>
  );
};

export default PlaybookFlowFieldActions;
