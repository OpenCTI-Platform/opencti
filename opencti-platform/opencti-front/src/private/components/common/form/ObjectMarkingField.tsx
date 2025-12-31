import React, { FunctionComponent, useEffect, useState } from 'react';
import { Field } from 'formik';
import { graphql } from 'react-relay';
import makeStyles from '@mui/styles/makeStyles';
import Button from '@common/button/Button';
import Dialog from '@mui/material/Dialog';
import DialogActions from '@mui/material/DialogActions';
import DialogContent from '@mui/material/DialogContent';
import DialogContentText from '@mui/material/DialogContentText';
import { ObjectMarkingFieldAllowedMarkingQuery$data } from '@components/common/form/__generated__/ObjectMarkingFieldAllowedMarkingQuery.graphql';
import { ObjectMarkingFieldOtherUserAllowedMarkingsQuery$data } from '@components/common/form/__generated__/ObjectMarkingFieldOtherUserAllowedMarkingsQuery.graphql';
import DialogTitle from '@mui/material/DialogTitle';
import { useTheme } from '@mui/material/styles';
import useAuth from '../../../../utils/hooks/useAuth';
import Transition from '../../../../components/Transition';
import AutocompleteField from '../../../../components/AutocompleteField';
import { RenderOption } from '../../../../components/list_lines';
import { useFormatter } from '../../../../components/i18n';
import { convertMarking } from '../../../../utils/edition';
import { filterMarkingsOutFor } from '../../../../utils/markings/markingsFiltering';
import { isEmptyField } from '../../../../utils/utils';
import { fetchQuery } from '../../../../relay/environment';
import { FieldOption } from '../../../../utils/field';
import type { Theme } from '../../../../components/Theme';
import MarkingIcon from '../../../../utils/MarkingIcon';

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

const objectMarkingFieldOtherUserAllowedMarkingsQuery = graphql`
  query ObjectMarkingFieldOtherUserAllowedMarkingsQuery($filters: FilterGroup) {
    markingDefinitions(filters: $filters) {
      edges {
        node {
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
  }
`;

const objectMarkingFieldAllowedMarkingQuery = graphql`
  query ObjectMarkingFieldAllowedMarkingQuery($id: String!) {
    user(id: $id) {
      groups(orderBy: name) {
        edges {
          node {
            allowed_marking {
              id
            }
          }
        }
      }
    }
  }
`;

interface ObjectMarkingFieldProps {
  name: string;
  required?: boolean;
  style?: React.CSSProperties;
  onChange?: (
    name: string,
    values: FieldOption[],
    operation?: string | undefined,
  ) => void;
  isOptionEqualToValue?: (option: FieldOption, value: FieldOption) => boolean;
  helpertext?: unknown;
  disabled?: boolean;
  label?: string;
  allowedMarkingOwnerId?: string;
  setFieldValue?: (name: string, values: FieldOption[]) => void;
  limitToMaxSharing?: boolean;
  filterTargetIds?: string[];
}

interface MarkingOption extends FieldOption {
  definition_type: string;
  x_opencti_order: number;
}

interface OptionValues {
  currentValues: MarkingOption[];
  valueToReplace: MarkingOption;
}

const ObjectMarkingField: FunctionComponent<ObjectMarkingFieldProps> = ({
  name,
  style,
  onChange,
  helpertext,
  disabled,
  label,
  allowedMarkingOwnerId,
  setFieldValue,
  limitToMaxSharing = false,
  filterTargetIds,
  isOptionEqualToValue,
  required = false,
}) => {
  const classes = useStyles();
  const { t_i18n } = useFormatter();
  const theme = useTheme<Theme>();
  const [newMarking, setNewMarking] = useState<
  FieldOption[] | OptionValues | undefined
  >(undefined);
  const [operation, setOperation] = useState<string | undefined>(undefined);
  const [otherUserAllowedMarkingsData, setOtherUserAllowedMarkingsData] = useState(
    [] as { definition: string | null | undefined; id: string; x_opencti_color: string | null | undefined }[] | undefined,
  );

  const fetchCreatorAllowedMarking = async (creatorId: string) => {
    return fetchQuery(objectMarkingFieldAllowedMarkingQuery, {
      id: creatorId,
    })
      .toPromise();
  };

  const fetchCreatorAllowedMarkings = async (creatorAllowedMarkingIds: string[]) => {
    if (creatorAllowedMarkingIds.length) {
      return fetchQuery(objectMarkingFieldOtherUserAllowedMarkingsQuery, {
        filters: {
          mode: 'and',
          filters: {
            mode: 'or',
            key: 'id',
            values: creatorAllowedMarkingIds,
            operator: 'eq',
          },
          filterGroups: [],
        },
      })
        .toPromise();
    }
    return {
      markingDefinitions: {
        edges: [],
      },
    };
  };

  useEffect(() => {
    if (allowedMarkingOwnerId) {
      const fetchData = async () => {
        const creatorAllowedMarkingIds = ((await fetchCreatorAllowedMarking(allowedMarkingOwnerId) as unknown as ObjectMarkingFieldAllowedMarkingQuery$data)
          .user?.groups?.edges ?? [])
          .flatMap((group) => (group?.node?.allowed_marking ?? [])
            .map((marking) => marking.id));
        const markingsData = ((await fetchCreatorAllowedMarkings(creatorAllowedMarkingIds) as unknown as ObjectMarkingFieldOtherUserAllowedMarkingsQuery$data)
          ?.markingDefinitions?.edges
          .map((marking) => ({ ...marking.node })));
        setOtherUserAllowedMarkingsData(markingsData);
      };
      fetchData();
    }
  }, [allowedMarkingOwnerId]);

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

  const otherUserAllowedMarkings = otherUserAllowedMarkingsData?.map(convertMarking) ?? [];

  const optionSorted = (otherUserAllowedMarkings.length ? otherUserAllowedMarkings : filteredAllowedMarkingDefinitionsOut).sort((a, b) => {
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

      onChange?.(name, markingsReplace as FieldOption[], operation);
      setFieldValue?.(name, markingsReplace);
      setOperation(undefined);
      handleClose();
    }
  };
  const handleOnChange = (n: string, values: MarkingOption[]) => {
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
    <li {...props} key={option.value}>
      <div className={classes.icon} style={{ color: option.color }}>
        <MarkingIcon theme={theme} color={option.color} />
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
        required={required}
        multiple={true}
        disabled={disabled}
        textfieldprops={{
          variant: 'standard',
          label: label ?? t_i18n('Markings'),
          helperText: helpertext,
        }}
        noOptionsText={t_i18n('No available options')}
        options={optionSorted}
        isOptionEqualToValue={isOptionEqualToValue}
        onChange={handleOnChange}
        renderOption={renderOption}
      />
      <Dialog
        slotProps={{ paper: { elevation: 1 } }}
        open={!!newMarking}
        keepMounted={true}
        slots={{ transition: Transition }}
        onClose={handleCancellation}
      >
        <DialogTitle>
          {t_i18n('Are you sure?')}
        </DialogTitle>
        <DialogContent>
          <DialogContentText>
            {t_i18n('You are about to change the marking with another rank.')}
          </DialogContentText>
        </DialogContent>
        <DialogActions>
          <Button variant="secondary" onClick={handleCancellation}>{t_i18n('Cancel')}</Button>
          <Button onClick={submitUpdate}>
            {t_i18n('Confirm')}
          </Button>
        </DialogActions>
      </Dialog>
    </>
  );
};

export default ObjectMarkingField;
