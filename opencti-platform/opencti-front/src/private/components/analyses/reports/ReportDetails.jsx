import React, { useEffect, useRef, useState } from 'react';
import { graphql, useFragment } from 'react-relay';
import Paper from '@mui/material/Paper';
import Chip from '@mui/material/Chip';
import Typography from '@mui/material/Typography';
import Grid from '@mui/material/Grid';
import makeStyles from '@mui/styles/makeStyles';
import RelatedContainers from '../../common/containers/RelatedContainers';
import StixRelationshipsHorizontalBars from '../../common/stix_relationships/StixRelationshipsHorizontalBars';
import { useFormatter } from '../../../../components/i18n';
import ExpandableMarkdown from '../../../../components/ExpandableMarkdown';
import FieldOrEmpty from '../../../../components/FieldOrEmpty';
import { emptyFilterGroup } from '../../../../utils/filters/filtersUtils';

const useStyles = makeStyles((theme) => ({
  paper: {
    marginTop: theme.spacing(1),
    padding: theme.spacing(2),
    borderRadius: 4,
    position: 'relative',
  },
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
      orderBy: published
      orderMode: desc
      types: ["Case", "Report", "Grouping"]
      viaTypes: ["Indicator", "Stix-Cyber-Observable"]
    ) {
      edges {
        node {
          id
          entity_type
          objectMarking {
            id
            definition_type
            definition
            x_opencti_order
            x_opencti_color
          }
          createdBy {
            ... on Identity {
              id
              name
              entity_type
            }
          }
          ... on Report {
            name
            published
          }
          ... on Grouping {
            name
            created
          }
          ... on CaseIncident {
            name
            created
          }
          ... on CaseRfi {
            name
            created
          }
          ... on CaseRft {
            name
            created
          }
        }
      }
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
    <div style={{ height: '100%' }} data-testid='report-overview'>
      <Typography variant="h4" gutterBottom={true}>
        {t_i18n('Entity details')}
      </Typography>
      <Paper classes={{ root: classes.paper }} className={'paper-for-grid'} variant="outlined">
        <Grid container={true} spacing={3} style={{ marginBottom: 20 }}>
          <Grid item xs={6} ref={ref}>
            <Typography variant="h3" gutterBottom={true}>
              {t_i18n('Description')}
            </Typography>
            <ExpandableMarkdown source={reportData.description} limit={400} />
            <Typography
              variant="h3"
              gutterBottom={true}
              style={{ marginTop: 20 }}
            >
              {t_i18n('Report types')}
            </Typography>
            <FieldOrEmpty source={reportData.report_types}>
              {reportData.report_types?.map((reportType) => (
                <Chip
                  key={reportType}
                  classes={{ root: classes.chip }}
                  label={reportType}
                />
              ))}
            </FieldOrEmpty>
            <Typography
              variant="h3"
              gutterBottom={true}
              style={{ marginTop: 20 }}
            >
              {t_i18n('Publication date')}
            </Typography>
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
        <RelatedContainers
          relatedContainers={reportData.relatedContainers}
          containerId={reportData.id}
          entityType={reportData.entity_type}
        />
      </Paper>
    </div>
  );
};

export default ReportDetails;
