import React, { useEffect, useRef, useState } from 'react';
import { graphql, useFragment } from 'react-relay';
import Chip from '@mui/material/Chip';
import Grid from '@mui/material/Grid';
import makeStyles from '@mui/styles/makeStyles';
import Divider from '@mui/material/Divider';
import Card from '@common/card/Card';
import RelatedContainers from '../../common/containers/related_containers/RelatedContainers';
import StixRelationshipsHorizontalBars from '../../common/stix_relationships/StixRelationshipsHorizontalBars';
import { useFormatter } from '../../../../components/i18n';
import ExpandableMarkdown from '../../../../components/ExpandableMarkdown';
import FieldOrEmpty from '../../../../components/FieldOrEmpty';
import { emptyFilterGroup } from '../../../../utils/filters/filtersUtils';
import Label from '../../../../components/common/label/Label';

const useStyles = makeStyles((theme) => ({
  chip: {
    fontSize: 12,
    lineHeight: '12px',
    backgroundColor: theme.palette.background.accent,
    color: theme.palette.text.primary,
    textTransform: 'uppercase',
    borderRadius: 4,
    margin: '0 5px 5px 0',
  },
}));

const ReportDetailsFragment = graphql`
  fragment ReportDetails_report on Report {
    id
    entity_type
    published
    report_types
    description
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

const ReportDetails = ({ report }) => {
  const classes = useStyles();
  const { t_i18n, fldt } = useFormatter();
  const [height, setHeight] = useState(0);
  const ref = useRef(null);
  const reportData = useFragment(ReportDetailsFragment, report);
  useEffect(() => {
    setHeight(ref.current.clientHeight);
  });

  const entitiesDistributionDataSelection = [
    {
      label: '',
      attribute: 'entity_type',
      date_attribute: 'first_seen',
      perspective: 'relationships',
      isTo: true,
      filters: {
        mode: 'and',
        filters: [
          {
            key: 'relationship_type',
            values: [
              'object',
            ],
            operator: 'eq',
            mode: 'or',
          },
        ],
        filterGroups: [],
      },
      dynamicFrom: emptyFilterGroup,
      dynamicTo: emptyFilterGroup,
    },
  ];

  return (
    <div style={{ height: '100%' }} data-testid="report-overview">
      <Card title={t_i18n('Entity details')}>
        <Grid container={true} spacing={3}>
          <Grid item xs={6} ref={ref}>
            <Label>{t_i18n('Description')}</Label>
            <ExpandableMarkdown source={reportData.description} limit={400} />
            <Label sx={{ mt: 2 }}>{t_i18n('Report types')}</Label>
            <FieldOrEmpty source={reportData.report_types}>
              {reportData.report_types?.map((reportType) => (
                <Chip
                  key={reportType}
                  classes={{ root: classes.chip }}
                  label={reportType}
                />
              ))}
            </FieldOrEmpty>
            <Label sx={{ mt: 2 }}>{t_i18n('Publication date')}</Label>
            {fldt(reportData.published)}
          </Grid>
          <Grid
            item
            xs={6}
            style={{ minHeight: 200, maxHeight: height }}
          >
            <StixRelationshipsHorizontalBars
              isWidget={false}
              fromId={reportData.id}
              startDate={null}
              endDate={null}
              relationshipType="object"
              dataSelection={entitiesDistributionDataSelection}
              parameters={{ title: 'Entities distribution' }}
              variant="inEntity"
              isReadOnly={true}
            />
          </Grid>
        </Grid>
        <Divider sx={{ marginTop: 3 }} />
        <RelatedContainers
          relatedContainers={reportData.relatedContainers}
          containerId={reportData.id}
          entityType={reportData.entity_type}
        />
      </Card>
    </div>
  );
};

export default ReportDetails;
