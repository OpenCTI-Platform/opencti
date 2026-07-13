import Grid from '@mui/material/Grid';
import React, { FunctionComponent } from 'react';
import { graphql, useFragment, useLazyLoadQuery } from 'react-relay';
import RelatedContainers from '@components/common/containers/related_containers/RelatedContainers';
import Divider from '@mui/material/Divider';
import ExpandableMarkdown from '../../../../components/ExpandableMarkdown';
import { useFormatter } from '../../../../components/i18n';
import ItemOpenVocab from '../../../../components/ItemOpenVocab';
import { CaseIncidentDetails_case$key } from './__generated__/CaseIncidentDetails_case.graphql';
import Card from '../../../../components/common/card/Card';
import Label from '../../../../components/common/label/Label';
import FieldOrEmpty from '../../../../components/FieldOrEmpty';
import Tag from '../../../../components/common/tag/Tag';
import { Stack } from '@mui/material';
import { CaseIncidentCustomFieldsQuery } from './__generated__/CaseIncidentCustomFieldsQuery.graphql';
import { customFieldDefinitionsForEntityTypeQuery } from './CaseIncidentCustomFields';

const CASE_INCIDENT_TYPE = 'Case-Incident';

const CaseIncidentDetailsFragment = graphql`
  fragment CaseIncidentDetails_case on CaseIncident {
    id
    name
    entity_type
    description
    priority
    severity
    created
    modified
    created_at
    response_types
    objectLabel {
      id
      value
      color
    }
    name
    x_opencti_stix_ids
    status {
      id
      order
      template {
        name
        color
      }
    }
    workflowEnabled
    customFieldValues {
      field_id
      field_name
      int_value
      string_value
      boolean_value
      date_value
      select_value
      select_values
    }
    relatedContainers(
      first: 10
      orderBy: modified
      orderMode: desc
      types: ["Case", "Report", "Grouping"]
      viaTypes: ["Indicator", "Stix-Cyber-Observable"]
    ) {
      ...RelatedContainersFragment_container_connection
    }
  }
`;

// Formats a raw custom field name (e.g. "risk_score") into a human-readable label ("Risk score").
const formatCustomFieldLabel = (fieldName: string) => {
  const spaced = fieldName.replace(/_/g, ' ');
  return spaced.charAt(0).toUpperCase() + spaced.slice(1);
};

interface CaseIncidentDetailsProps {
  caseIncidentData: CaseIncidentDetails_case$key;
}

const CaseIncidentDetails: FunctionComponent<CaseIncidentDetailsProps> = ({
  caseIncidentData,
}) => {
  const { t_i18n, fsd } = useFormatter();
  const data = useFragment(CaseIncidentDetailsFragment, caseIncidentData);
  const responseTypes = data.response_types ?? [];
  const customFieldValues = data.customFieldValues ?? [];
  const customFieldData = useLazyLoadQuery<CaseIncidentCustomFieldsQuery>(
    customFieldDefinitionsForEntityTypeQuery,
    { entityType: CASE_INCIDENT_TYPE },
  );
  const customFieldLabelById = new Map(
    (customFieldData.customFieldDefinitionsForEntityType?.edges ?? []).map((edge) => [edge.node.id, edge.node.label]),
  );

  const getCustomFieldDisplayValue = (cfv: NonNullable<typeof customFieldValues>[number]) => {
    if (cfv.boolean_value !== null && cfv.boolean_value !== undefined) {
      return cfv.boolean_value ? t_i18n('True') : t_i18n('False');
    }
    if (cfv.date_value) {
      return fsd(cfv.date_value);
    }
    if (cfv.int_value !== null && cfv.int_value !== undefined) {
      return String(cfv.int_value);
    }
    if (cfv.select_values && cfv.select_values.length > 0) {
      return cfv.select_values.join(', ');
    }
    if (cfv.select_value) {
      return cfv.select_value;
    }
    return cfv.string_value ?? '';
  };

  return (
    <div style={{ height: '100%' }}>
      <Card title={t_i18n('Details')}>
        <Grid container={true} spacing={2} sx={{ marginBottom: 2 }}>
          <Grid item xs={12}>
            <Label>
              {t_i18n('Description')}
            </Label>
            <FieldOrEmpty source={data.description}>
              <ExpandableMarkdown source={data.description} limit={300} />
            </FieldOrEmpty>
          </Grid>
          <Grid item xs={6}>
            <Label>
              {t_i18n('Priority')}
            </Label>
            <ItemOpenVocab
              key="type"
              small={true}
              type="case_priority_ov"
              value={data.priority}
              displayMode="chip"
            />
          </Grid>
          <Grid item xs={6}>
            <Label>
              {t_i18n('Severity')}
            </Label>
            <ItemOpenVocab
              key="type"
              small={true}
              type="case_severity_ov"
              value={data.severity}
              displayMode="chip"
            />
          </Grid>
          <Grid item xs={6}>
            <Label>
              {t_i18n('Incident response type')}
            </Label>
            <FieldOrEmpty source={responseTypes}>
              <Stack direction="row" flexWrap="wrap" gap={1}>
                {responseTypes.map((responseType) => (
                  <Tag
                    key={responseType}
                    label={responseType}
                  />
                ))}
              </Stack>
            </FieldOrEmpty>
          </Grid>
          {customFieldValues.map((cfv) => (
            <Grid item xs={6} key={cfv.field_id}>
              <Label>
                {customFieldLabelById.get(cfv.field_id) ?? formatCustomFieldLabel(cfv.field_name)}
              </Label>
              <FieldOrEmpty source={getCustomFieldDisplayValue(cfv)}>
                <Tag label={getCustomFieldDisplayValue(cfv)} />
              </FieldOrEmpty>
            </Grid>
          ))}
        </Grid>
        <Divider />
        <RelatedContainers
          relatedContainers={data.relatedContainers}
          containerId={data.id}
          entityType={data.entity_type}
        />
      </Card>
    </div>
  );
};
export default CaseIncidentDetails;
