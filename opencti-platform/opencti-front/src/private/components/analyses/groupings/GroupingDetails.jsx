import React, { useState, useRef, useEffect } from 'react';
import * as PropTypes from 'prop-types';
import * as R from 'ramda';
import { graphql, createFragmentContainer } from 'react-relay';
import withStyles from '@mui/styles/withStyles';
import Paper from '@mui/material/Paper';
import Chip from '@mui/material/Chip';
import Typography from '@mui/material/Typography';
import Grid from '@mui/material/Grid';
import RelatedContainers from '../../common/containers/RelatedContainers';
import StixRelationshipsHorizontalBars from '../../common/stix_relationships/StixRelationshipsHorizontalBars';
import inject18n from '../../../../components/i18n';
import ExpandableMarkdown from '../../../../components/ExpandableMarkdown';
import { emptyFilterGroup } from '../../../../utils/filters/filtersUtils';

const styles = (theme) => ({
  paper: {
    marginTop: theme.spacing(1),
    padding: '15px',
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
  item: {
    height: 50,
    minHeight: 50,
    maxHeight: 50,
    paddingRight: 0,
  },
  itemText: {
    whiteSpace: 'nowrap',
    overflow: 'hidden',
    textOverflow: 'ellipsis',
    paddingRight: 10,
  },
  itemIcon: {
    marginRight: 0,
    color: theme.palette.primary.main,
  },
  itemIconDisabled: {
    marginRight: 0,
    color: theme.palette.grey[700],
  },
  buttonExpand: {
    position: 'absolute',
    left: 0,
    bottom: 0,
    width: '100%',
    height: 25,
    color: theme.palette.primary.main,
    backgroundColor:
      theme.palette.mode === 'dark'
        ? 'rgba(255, 255, 255, .1)'
        : 'rgba(0, 0, 0, .1)',
    borderTopLeftRadius: 0,
    borderTopRightRadius: 0,
    '&:hover': {
      backgroundColor:
        theme.palette.mode === 'dark'
          ? 'rgba(255, 255, 255, .2)'
          : 'rgba(0, 0, 0, .2)',
    },
  },
});

const GroupingDetailsComponent = (props) => {
  const { t, classes, grouping } = props;
  const [height, setHeight] = useState(0);
  const ref = useRef(null);
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
    <div style={{ height: '100%' }}>
      <Typography variant="h4" gutterBottom={true}>
        {t('Entity details')}
      </Typography>
      <Paper classes={{ root: classes.paper }} className={'paper-for-grid'} variant="outlined">
        <Grid container={true} spacing={3} style={{ marginBottom: 20 }}>
          <Grid item xs={6} ref={ref}>
            <Typography variant="h3" gutterBottom={true}>
              {t('Description')}
            </Typography>
            <ExpandableMarkdown source={grouping.description} limit={400} />
            <Typography
              variant="h3"
              gutterBottom={true}
              style={{ marginTop: 20 }}
            >
              {t('Context')}
            </Typography>
            <Chip classes={{ root: classes.chip }} label={grouping.context} />
          </Grid>
          <Grid item xs={6} style={{ minHeight: 200, maxHeight: height }}>
            <StixRelationshipsHorizontalBars
              isWidget={false}
              fromId={grouping.id}
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
          relatedContainers={grouping.relatedContainers}
          containerId={grouping.id}
          entityType={grouping.entity_type}
        />
      </Paper>
    </div>
  );
};

GroupingDetailsComponent.propTypes = {
  grouping: PropTypes.object,
  classes: PropTypes.object,
  t: PropTypes.func,
  fld: PropTypes.func,
};

const GroupingDetails = createFragmentContainer(GroupingDetailsComponent, {
  grouping: graphql`
    fragment GroupingDetails_grouping on Grouping {
      id
      entity_type
      context
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
`,
});

export default R.compose(inject18n, withStyles(styles))(GroupingDetails);
