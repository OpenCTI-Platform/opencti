import Grid from '@mui/material/Grid';
import React, { FunctionComponent } from 'react';
import { graphql, useFragment } from 'react-relay';
import RelatedContainers from '@components/common/containers/related_containers/RelatedContainers';
import Divider from '@mui/material/Divider';
import ExpandableMarkdown from '../../../../components/ExpandableMarkdown';
import { useFormatter } from '../../../../components/i18n';
import ItemOpenVocab from '../../../../components/ItemOpenVocab';
import { CaseRftDetails_case$key } from './__generated__/CaseRftDetails_case.graphql';
import Card from '../../../../components/common/card/Card';
import Label from '../../../../components/common/label/Label';
import FieldOrEmpty from '../../../../components/FieldOrEmpty';
import Tag from '../../../../components/common/tag/Tag';

const CaseRftDetailsFragment = graphql`
  fragment CaseRftDetails_case on CaseRft {
    id
    name
    entity_type
    description
    created
    modified
    created_at
    takedown_types
    priority
    severity
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

interface CaseRftDetailsProps {
  caseRftData: CaseRftDetails_case$key;
}

const CaseRftDetails: FunctionComponent<CaseRftDetailsProps> = ({
  caseRftData,
}) => {
  const { t_i18n } = useFormatter();
  const data = useFragment(CaseRftDetailsFragment, caseRftData);
  const takedownTypes = data.takedown_types ?? [];

  return (
    <div style={{ height: '100%' }} data-testid="case-rft-details-page">
      <Card title={t_i18n('Details')}>
        <Grid container={true} spacing={2} sx={{ marginBottom: 2 }}>
          <Grid item xs={6}>
            <Label>
              {t_i18n('Takedown type')}
            </Label>
            <FieldOrEmpty source={takedownTypes}>
              {takedownTypes.map((takedownType) => (
                <Tag
                  key={takedownType}
                  label={takedownType}
                />
              ))}
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
          <Grid item xs={12}>
            <Label>
              {t_i18n('Description')}
            </Label>
            <FieldOrEmpty source={data.description}>
              <ExpandableMarkdown source={data.description} limit={300} />
            </FieldOrEmpty>
          </Grid>
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
export default CaseRftDetails;
