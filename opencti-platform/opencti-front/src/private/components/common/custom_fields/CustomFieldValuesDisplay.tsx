import { FunctionComponent, Suspense, useState } from 'react';
import Grid from '@mui/material/Grid';
import { graphql } from 'react-relay';
import Label from '../../../../components/common/label/Label';
import Tag from '../../../../components/common/tag/Tag';
import FieldOrEmpty from '../../../../components/FieldOrEmpty';
import ExpandableMarkdown from '../../../../components/ExpandableMarkdown';
import { useFormatter } from '../../../../components/i18n';
import { CustomFieldDef, CustomFieldStoredValue, getCustomFieldDisplayValue, getCustomFieldLabel } from '../../../../utils/customFields';
import { CustomFieldsLoader } from './CustomFieldsInput';

// Shared by the owning Details fragments so entity updates refresh the displayed values.
export const customFieldValuesDisplayFragment = graphql`
  fragment CustomFieldValuesDisplay_values on CustomFieldValue {
    field_id
    field_name
    int_value
    string_value
    boolean_value
    date_value
    select_value
    select_values
  }
`;

interface CustomFieldValuesDisplayProps {
  entityType: string;
  values: readonly CustomFieldStoredValue[];
}

// Renders grid items inside the entity's details grid, without adding another container.
const CustomFieldValuesDisplay: FunctionComponent<CustomFieldValuesDisplayProps> = ({ entityType, values }) => {
  const { t_i18n, fldt } = useFormatter();
  const [definitions, setDefinitions] = useState<CustomFieldDef[]>([]);

  return (
    <>
      {values.length > 0 && (
        <Suspense fallback={null}>
          <CustomFieldsLoader entityType={entityType} onLoaded={setDefinitions} />
        </Suspense>
      )}
      {values.map((value) => {
        const displayValue = getCustomFieldDisplayValue(value, { t_i18n, fldt });
        // A markdown custom field is displayed as the description: full width, rendered and expandable
        const isMarkdown = definitions.find((definition) => definition.id === value.field_id)?.field_type === 'markdown';
        return (
          <Grid key={value.field_id} size={isMarkdown ? 12 : 6}>
            <Label>{getCustomFieldLabel(value, definitions)}</Label>
            <FieldOrEmpty source={displayValue}>
              {isMarkdown ? <ExpandableMarkdown source={displayValue} limit={300} /> : <Tag label={displayValue} />}
            </FieldOrEmpty>
          </Grid>
        );
      })}
    </>
  );
};

export default CustomFieldValuesDisplay;
