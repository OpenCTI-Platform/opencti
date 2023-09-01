import React, { useState, FunctionComponent } from 'react';
import { Field } from 'formik';
import { graphql } from 'react-relay';
import makeStyles from '@mui/styles/makeStyles';
import { useFormatter } from '../../../../components/i18n';
import { RenderOption } from '../../../../components/list_lines';
import { Option } from './ReferenceField';
import useAuth from '../../../../utils/hooks/useAuth';
import AutocompleteField from '../../../../components/AutocompleteField';
import ItemIcon from '../../../../components/ItemIcon';

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

interface MarkingDefinitionProps {
  id: string;
  definition: string;
  definition_type: string;
  entity_type: string;
  standard_id: string;
  x_opencti_color: string;
  x_opencti_order: number;
}

interface MarkingDefinition {
  label: string;
  value: string;
  color: string;
  entity: MarkingDefinitionProps;
}
interface ObjectMarkingFieldProps {
  name: string;
  style?: React.CSSProperties;
  onChange?: (name: string, value: Option[]) => void;
  helpertext?: unknown;
  disabled?: boolean;
  label: string;
  defaultMarkingDefinitions?: MarkingDefinitionProps[];
}

const ObjectMarkingField: FunctionComponent<ObjectMarkingFieldProps> = ({
  name,
  style,
  onChange,
  helpertext,
  disabled,
  label,
  defaultMarkingDefinitions,
}) => {
  const classes = useStyles();
  const { t } = useFormatter();

  const [markingDefinitions, setMarkingDefinitions] = useState<MarkingDefinition[]>(defaultMarkingDefinitions ? defaultMarkingDefinitions.map((m : MarkingDefinitionProps) => ({
    label: m.definition,
    value: m.id,
    color: m.x_opencti_color,
    entity: m,
  })) : []);

  const { me } = useAuth();
  const searchMarkingDefinitions = () => {
    const allowedMarkingDefinitions : any[] = me.allowed_marking ? me.allowed_marking.map((m) => ({
      label: m.definition,
      value: m.id,
      color: m.x_opencti_color,
      entity: m,
    })) : [];
    setMarkingDefinitions(allowedMarkingDefinitions);
  };

  const optionSorted = markingDefinitions.sort((a, b) => {
    if (a.entity.definition_type === b.entity.definition_type) {
      return (a.entity.x_opencti_order < b.entity.x_opencti_order ? -1 : 1);
    } return (a.entity.definition_type < b.entity.definition_type ? -1 : 1);
  });

  const renderOption: RenderOption = (props, option) => (
      <li {...props}>
          <div className={classes.icon} style={{ color: option.color }}>
              <ItemIcon type="Marking-Definition" color={option.color}/>
          </div>
          <div className={classes.text}>{option.label}</div>
      </li>
  );

  return (
        <Field
            component={AutocompleteField}
            style={style}
            name={name}
            multiple={true}
            disabled={disabled}
            textfieldprops={{
              variant: 'standard',
              label: label ?? t('Markings'),
              helperText: helpertext,
              onFocus: searchMarkingDefinitions,
            }}
            noOptionsText={t('No available options')}
            options={optionSorted}
            onInputChange={searchMarkingDefinitions}
            onChange={typeof onChange === 'function' ? onChange : null}
            renderOption={renderOption}
        />
  );
};

export default ObjectMarkingField;
