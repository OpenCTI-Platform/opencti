import React, { FunctionComponent, useState } from 'react';
import { Field } from 'formik';
import { graphql } from 'react-relay';
import makeStyles from '@mui/styles/makeStyles';
import Button from '@mui/material/Button';
import Dialog from '@mui/material/Dialog';
import DialogActions from '@mui/material/DialogActions';
import DialogContent from '@mui/material/DialogContent';
import DialogContentText from '@mui/material/DialogContentText';
import useAuth from '../../../../utils/hooks/useAuth';
import ItemIcon from '../../../../components/ItemIcon';
import Transition from '../../../../components/Transition';
import AutocompleteField from '../../../../components/AutocompleteField';
import { RenderOption } from '../../../../components/list_lines';
import { useFormatter } from '../../../../components/i18n';
import { convertMarking } from '../../../../utils/edition';
import { Option } from './ReferenceField';
import { filterMarkingsOutFor } from '../../../../utils/markings/markingsFiltering';
import { isEmptyField } from '../../../../utils/utils';

// Deprecated - https://mui.com/system/styles/basics/
// Do not use it for new code.
const useStyles = makeStyles(() => ({
  icon: {
    paddingTop: 4,
    display: 'inline-block',
  },
  text: {
    display: 'inline-block',
    flexGrow: 1,
    marginLeft: 10,
  },
}));

export const objectMarkingFieldAllowedMarkingsQuery = graphql`
  query ObjectMarkingFieldAllowedMarkingsQuery {
    me {
      allowed_marking {
        id
        entity_type
        standard_id
        definition_type
        definition
        x_opencti_color
        x_opencti_order
      }
    }
  }
`;

interface ObjectMarkingFieldProps {
  name: string;
  style?: React.CSSProperties;
  onChange?: (
    name: string,
    values: Option[],
    operation?: string | undefined,
  ) => void;
  helpertext?: unknown;
  disabled?: boolean;
  label?: string;
  setFieldValue?: (name: string, values: Option[]) => void;
  limitToMaxSharing?: boolean;
  filterTargetIds?: string[];
}

interface OptionValues {
  currentValues: Option[];
  valueToReplace: Option;
}

const ObjectMarkingField: FunctionComponent<ObjectMarkingFieldProps> = ({
  name,
  style,
  onChange,
  helpertext,
  disabled,
  label,
  setFieldValue,
  limitToMaxSharing = false,
  filterTargetIds,
}) => {
  const classes = useStyles();
  const { t_i18n } = useFormatter();
  const [newMarking, setNewMarking] = useState<
  Option[] | OptionValues | undefined
  >(undefined);
  const [operation, setOperation] = useState<string | undefined>(undefined);

  const { me } = useAuth();
  let allowedMarkingDefinitions = me.allowed_marking?.map(convertMarking) ?? [];
  if (limitToMaxSharing) {
    allowedMarkingDefinitions = allowedMarkingDefinitions.filter((def) => {
      const maxMarkingsOfType = me.max_shareable_marking?.filter((marking) => marking.definition_type === def.definition_type);
      return !isEmptyField(maxMarkingsOfType) && maxMarkingsOfType.some((maxMarking) => maxMarking.x_opencti_order >= def.x_opencti_order);
    });
  }
  const filteredAllowedMarkingDefinitionsOut = filterTargetIds
    ? filterMarkingsOutFor(allowedMarkingDefinitions.filter(({ value }) => filterTargetIds.includes(value)), allowedMarkingDefinitions) : allowedMarkingDefinitions;

  const optionSorted = filteredAllowedMarkingDefinitionsOut.sort((a, b) => {
    if (a.definition_type === b.definition_type) {
      return a.x_opencti_order < b.x_opencti_order ? -1 : 1;
    }
    return a.definition_type < b.definition_type ? -1 : 1;
  });
  const handleClose = () => {
    setNewMarking(undefined);
  };
  const handleCancellation = () => {
    if (operation === 'replace') {
      const { currentValues } = newMarking as OptionValues;
      currentValues.pop();
      setFieldValue?.(name, currentValues);
    }
    handleClose();
  };
  const submitUpdate = () => {
    if (operation === 'replace') {
      const { currentValues, valueToReplace } = newMarking as OptionValues;
      const markingAdded = currentValues[currentValues.length - 1];
      const markingsReplace = currentValues
        .filter(
          (marking) => marking.definition_type !== valueToReplace.definition_type,
        )
        .concat([markingAdded]);

      onChange?.(name, markingsReplace as Option[], operation);
      setFieldValue?.(name, markingsReplace);
      setOperation(undefined);
      handleClose();
    }
  };
  const handleOnChange = (n: string, values: Option[]) => {
    const valueAdded = values[values.length - 1];
    const valueToReplace = values.find(
      (marking) => marking.definition_type === valueAdded.definition_type
        && marking.x_opencti_order !== valueAdded.x_opencti_order,
    );

    if (valueToReplace) {
      setOperation('replace');
      setNewMarking({ currentValues: values, valueToReplace });
    } else onChange?.(name, values);
  };

  const renderOption: RenderOption = (props, option) => (
    <li {...props}>
      <div className={classes.icon} style={{ color: option.color }}>
        <ItemIcon type="Marking-Definition" color={option.color} />
      </div>
      <div className={classes.text}>{option.label}</div>
    </li>
  );

  return (
    <>
      <Field
        component={AutocompleteField}
        style={style}
        name={name}
        multiple={true}
        disabled={disabled}
        textfieldprops={{
          variant: 'standard',
          label: label ?? t_i18n('Markings'),
          helperText: helpertext,
        }}
        noOptionsText={t_i18n('No available options')}
        options={optionSorted}
        onChange={handleOnChange}
        renderOption={renderOption}
      />
      <Dialog
        PaperProps={{ elevation: 1 }}
        open={!!newMarking}
        keepMounted={true}
        TransitionComponent={Transition}
        onClose={handleCancellation}
      >
        <DialogContent>
          <DialogContentText>
            {t_i18n('You are about to change the marking with another rank.')}
          </DialogContentText>
          <DialogContentText>
            {t_i18n('Are you sure you want to make the change?')}
          </DialogContentText>
        </DialogContent>
        <DialogActions>
          <Button onClick={handleCancellation}>{t_i18n('Cancel')}</Button>
          <Button color="secondary" onClick={submitUpdate}>
            {t_i18n('Replace')}
          </Button>
        </DialogActions>
      </Dialog>
    </>
  );
};

export default ObjectMarkingField;
