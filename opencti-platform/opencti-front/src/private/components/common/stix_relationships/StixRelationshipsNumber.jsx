import React from 'react';
import { graphql } from 'react-relay';
import CircularProgress from '@mui/material/CircularProgress';
import Paper from '@mui/material/Paper';
import Typography from '@mui/material/Typography';
import makeStyles from '@mui/styles/makeStyles';
import * as R from 'ramda';
import { QueryRenderer } from '../../../../relay/environment';
import { useFormatter } from '../../../../components/i18n';
import ItemNumberDifference from '../../../../components/ItemNumberDifference';
import { dayAgo } from '../../../../utils/Time';

const useStyles = makeStyles({
  paper: {
    minHeight: 280,
    height: '100%',
    margin: '4px 0 0 0',
    padding: '0 0 10px 0',
    borderRadius: 6,
  },
  number: {
    float: 'left',
    fontSize: 40,
  },
});

const stixRelationshipsNumberNumberQuery = graphql`
  query StixRelationshipsNumberNumberSeriesQuery(
    $noDirection: Boolean
    $endDate: DateTime
    $onlyInferred: Boolean
    $elementId: [String]
    $elementWithTargetTypes: [String]
    $fromId: [String]
    $fromRole: String
    $fromTypes: [String]
    $toId: [String]
    $toRole: String
    $toTypes: [String]
    $relationship_type: [String]
    $confidences: [Int]
    $search: String
    $filters: FilterGroup
    $dynamicFrom: FilterGroup
    $dynamicTo: FilterGroup
  ) {
    stixRelationshipsNumber(
      noDirection: $noDirection
      endDate: $endDate
      onlyInferred: $onlyInferred
      elementId: $elementId
      elementWithTargetTypes: $elementWithTargetTypes
      fromId: $fromId
      fromRole: $fromRole
      fromTypes: $fromTypes
      toId: $toId
      toRole: $toRole
      toTypes: $toTypes
      relationship_type: $relationship_type
      confidences: $confidences
      search: $search
      filters: $filters
      dynamicFrom: $dynamicFrom
      dynamicTo: $dynamicTo
    ) {
      total
      count
    }
  }
`;

const StixRelationshipsNumber = ({
  variant,
  height,
  startDate,
  dataSelection,
  parameters = {},
}) => {
  const classes = useStyles();
  const { t, n } = useFormatter();
  const renderContent = () => {
    const selection = dataSelection[0];
    let filtersContent = selection.filters.filters;
    const relationshipType = R.head(filtersContent.filter((o) => o.key === 'relationship_type'))
      ?.values || null;
    const elementId = R.head(filtersContent.filter((o) => o.key === 'elementId'))?.values || null;
    const elementWithTargetTypes = R.head(filtersContent.filter((o) => o.key === 'elementWithTargetTypes'))
      ?.values || null;
    const fromId = R.head(filtersContent.filter((o) => o.key === 'fromId'))?.values || null;
    const toId = R.head(filtersContent.filter((o) => o.key === 'toId'))?.values || null;
    const fromTypes = R.head(filtersContent.filter((o) => o.key === 'fromTypes'))?.values || null;
    const toTypes = R.head(filtersContent.filter((o) => o.key === 'toTypes'))?.values || null;
    filtersContent = filtersContent.filter(
      (o) => ![
        'relationship_type',
        'fromId',
        'toId',
        'fromTypes',
        'toTypes',
      ].includes(o.key),
    );
    return (
      <QueryRenderer
        query={stixRelationshipsNumberNumberQuery}
        variables={{
          elementId,
          elementWithTargetTypes,
          fromId,
          fromTypes,
          toId,
          toTypes,
          relationship_type: relationshipType,
          filters: selection.filters ? { ...selection.filters, filters: filtersContent } : undefined,
          startDate,
          endDate: dayAgo(),
          dynamicFrom: selection.dynamicFrom,
          dynamicTo: selection.dynamicTo,
        }}
        render={({ props }) => {
          if (props && props.stixRelationshipsNumber) {
            const { total } = props.stixRelationshipsNumber;
            const difference = total - props.stixRelationshipsNumber.count;
            return (
              <div>
                <div className={classes.number}>{n(total)}</div>
                <ItemNumberDifference
                  difference={difference}
                  description={t('24 hours')}
                />
              </div>
            );
          }
          if (props) {
            return (
              <div style={{ display: 'table', height: '100%', width: '100%' }}>
                <span
                  style={{
                    display: 'table-cell',
                    verticalAlign: 'middle',
                    textAlign: 'center',
                  }}
                >
                  {t('No entities of this type has been found.')}
                </span>
              </div>
            );
          }
          return (
            <div style={{ display: 'table', height: '100%', width: '100%' }}>
              <span
                style={{
                  display: 'table-cell',
                  verticalAlign: 'middle',
                  textAlign: 'center',
                }}
              >
                <CircularProgress size={40} thickness={2} />
              </span>
            </div>
          );
        }}
      />
    );
  };
  return (
    <div style={{ height: height || '100%' }}>
      <Typography
        variant="h4"
        gutterBottom={true}
        style={{
          margin: variant !== 'inLine' ? '0 0 10px 0' : '-10px 0 10px -7px',
          whiteSpace: 'nowrap',
          overflow: 'hidden',
          textOverflow: 'ellipsis',
        }}
      >
        {parameters.title ?? t('Entities number')}
      </Typography>
      {variant !== 'inLine' ? (
        <Paper classes={{ root: classes.paper }} variant="outlined">
          {renderContent()}
        </Paper>
      ) : (
        renderContent()
      )}
    </div>
  );
};

export default StixRelationshipsNumber;
