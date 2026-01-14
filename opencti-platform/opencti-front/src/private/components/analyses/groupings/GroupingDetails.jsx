import React, { useState, useRef, useEffect } from 'react';
import * as PropTypes from 'prop-types';
import * as R from 'ramda';
import { graphql, createFragmentContainer } from 'react-relay';
import withStyles from '@mui/styles/withStyles';
import Chip from '@mui/material/Chip';
import Grid from '@mui/material/Grid';
import Divider from '@mui/material/Divider';
import Card from '@common/card/Card';
import RelatedContainers from '../../common/containers/related_containers/RelatedContainers';
import StixRelationshipsHorizontalBars from '../../common/stix_relationships/StixRelationshipsHorizontalBars';
import inject18n from '../../../../components/i18n';
import ExpandableMarkdown from '../../../../components/ExpandableMarkdown';
import { emptyFilterGroup } from '../../../../utils/filters/filtersUtils';
import Label from '../../../../components/common/label/Label';

const styles = (theme) => ({
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
      <Card title={t('Entity details')}>
        <Grid container={true} spacing={3}>
          <Grid item xs={6} ref={ref}>
            <Label>
              {t('Description')}
            </Label>
            <ExpandableMarkdown source={grouping.description} limit={400} />
            <Label sx={{ marginTop: 2 }}>
              {t('Context')}
            </Label>
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
        <Divider sx={{ marginTop: 3 }} />
        <RelatedContainers
          relatedContainers={grouping.relatedContainers}
          containerId={grouping.id}
          entityType={grouping.entity_type}
        />
      </Card>
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
        orderBy: modified
        orderMode: desc
        types: ["Case", "Report", "Grouping"]
        viaTypes: ["Indicator", "Stix-Cyber-Observable"]
      ) {
        ...RelatedContainersFragment_container_connection
      }
    }
`,
});

export default R.compose(inject18n, withStyles(styles))(GroupingDetails);
