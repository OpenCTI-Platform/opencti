import React, { useEffect, useState } from 'react';
import Typography from '@mui/material/Typography';
import * as R from 'ramda';
import Grid from '@mui/material/Grid';
import TextField from '@mui/material/TextField';
import List from '@mui/material/List';
import ListItem from '@mui/material/ListItem';
import ListItemIcon from '@mui/material/ListItemIcon';
import ListItemText from '@mui/material/ListItemText';
import {
  ArrowDropDown,
  ArrowDropUp,
  KeyboardArrowRightOutlined,
} from '@mui/icons-material';
import makeStyles from '@mui/styles/makeStyles';
import { Link } from 'react-router-dom';
import Chip from '@mui/material/Chip';
import Box from '@mui/material/Box';
import LinearProgress from '@mui/material/LinearProgress';
import ItemIcon from '../../components/ItemIcon';
import { searchStixCoreObjectsLinesSearchQuery } from './search/SearchStixCoreObjectsLines';
import { fetchQuery } from '../../relay/environment';
import { useFormatter } from '../../components/i18n';
import { defaultValue } from '../../utils/Graph';
import { resolveLink } from '../../utils/Entity';
import StixCoreObjectLabels from './common/stix_core_objects/StixCoreObjectLabels';

const useStyles = makeStyles((theme) => ({
  linesContainer: {
    margin: 0,
  },
  itemHead: {
    paddingLeft: 10,
    textTransform: 'uppercase',
    cursor: 'pointer',
  },
  item: {
    paddingLeft: 10,
    height: 50,
  },
  bodyItem: {
    height: '100%',
    fontSize: 13,
  },
  itemIcon: {
    color: theme.palette.primary.main,
  },
  goIcon: {
    position: 'absolute',
    right: -10,
  },
  inputLabel: {
    float: 'left',
  },
  sortIcon: {
    float: 'left',
    margin: '-5px 0 0 15px',
  },
  icon: {
    color: theme.palette.primary.main,
  },
  chip: {
    fontSize: 13,
    lineHeight: '12px',
    height: 18,
    textTransform: 'uppercase',
    borderRadius: '0',
  },
}));

const inlineStylesHeaders = {
  iconSort: {
    position: 'absolute',
    margin: '0 0 0 5px',
    padding: 0,
    top: '0px',
  },
  type: {
    float: 'left',
    width: '15%',
    fontSize: 12,
    fontWeight: '700',
  },
  value: {
    float: 'left',
    width: '25%',
    fontSize: 12,
    fontWeight: '700',
  },
  labels: {
    float: 'left',
    width: '20%',
    fontSize: 12,
    fontWeight: '700',
  },
  author: {
    float: 'left',
    width: '10%',
    fontSize: 12,
    fontWeight: '700',
  },
  creator: {
    float: 'left',
    width: '10%',
    fontSize: 12,
    fontWeight: '700',
  },
  reports: {
    float: 'left',
    width: '10%',
    fontSize: 12,
    fontWeight: '700',
  },
  updated_at: {
    float: 'left',
    fontSize: 12,
    fontWeight: '700',
  },
};

const inlineStyles = {
  type: {
    float: 'left',
    width: '15%',
    height: 20,
    whiteSpace: 'nowrap',
    overflow: 'hidden',
    textOverflow: 'ellipsis',
  },
  value: {
    float: 'left',
    width: '25%',
    height: 20,
    whiteSpace: 'nowrap',
    overflow: 'hidden',
    textOverflow: 'ellipsis',
  },
  labels: {
    float: 'left',
    width: '20%',
    height: 20,
    whiteSpace: 'nowrap',
    overflow: 'hidden',
    textOverflow: 'ellipsis',
  },
  author: {
    float: 'left',
    width: '10%',
    height: 20,
    whiteSpace: 'nowrap',
    overflow: 'hidden',
    textOverflow: 'ellipsis',
  },
  creator: {
    float: 'left',
    width: '10%',
    height: 20,
    whiteSpace: 'nowrap',
    overflow: 'hidden',
    textOverflow: 'ellipsis',
  },
  reports: {
    float: 'left',
    width: '10%',
    height: 20,
    whiteSpace: 'nowrap',
    overflow: 'hidden',
    textOverflow: 'ellipsis',
  },
  updated_at: {
    float: 'left',
    height: 20,
    whiteSpace: 'nowrap',
    overflow: 'hidden',
    textOverflow: 'ellipsis',
  },
};

const SearchBulk = () => {
  const { t, nsd, n } = useFormatter();
  const classes = useStyles();
  const [textFieldValue, setTextFieldValue] = useState('');
  const [resolvedEntities, setResolvedEntities] = useState([]);
  const [sortBy, setSortBy] = useState(null);
  const [orderAsc, setOrderAsc] = useState(true);
  const [loading, setLoading] = useState(false);
  useEffect(() => {
    const fetchData = async () => {
      setLoading(true);
      const result = await Promise.all(
        textFieldValue
          .split('\n')
          .filter((o) => o.length > 1)
          .map((val) => {
            return fetchQuery(searchStixCoreObjectsLinesSearchQuery, {
              filters: [
                {
                  key: [
                    'name',
                    'aliases',
                    'x_opencti_aliases',
                    'x_mitre_id',
                    'value',
                    'subject',
                    'abstract',
                  ],
                  values: val.trim(),
                },
              ],
              count: 1,
            })
              .toPromise()
              .then((data) => {
                const stixCoreObjectsEdges = data.stixCoreObjects.edges;
                const firstStixCoreObject = R.head(stixCoreObjectsEdges)?.node;
                if (firstStixCoreObject) {
                  return {
                    id: firstStixCoreObject.id,
                    type: firstStixCoreObject.entity_type,
                    value: defaultValue(firstStixCoreObject),
                    labels: firstStixCoreObject.objectLabel,
                    markings: firstStixCoreObject.objectMarking,
                    reports: firstStixCoreObject.reports,
                    updated_at: firstStixCoreObject.updated_at,
                    author: R.pathOr(
                      '',
                      ['createdBy', 'name'],
                      firstStixCoreObject,
                    ),
                    creator: R.pathOr(
                      '',
                      ['creator', 'name'],
                      firstStixCoreObject,
                    ),
                    in_platform: true,
                  };
                }
                return {
                  id: val.trim(),
                  type: 'Unknown',
                  value: val.trim(),
                  in_platform: false,
                };
              });
          }),
      );
      setLoading(false);
      setResolvedEntities(result);
    };
    fetchData();
  }, [textFieldValue, setResolvedEntities]);
  const reverseBy = (field) => {
    setSortBy(field);
    setOrderAsc(!orderAsc);
  };
  const SortHeader = (field, label, isSortable) => {
    const sortComponent = orderAsc ? (
      <ArrowDropDown style={inlineStylesHeaders.iconSort} />
    ) : (
      <ArrowDropUp style={inlineStylesHeaders.iconSort} />
    );
    if (isSortable) {
      return (
        <div
          style={inlineStylesHeaders[field]}
          onClick={() => reverseBy(field)}
        >
          <span>{t(label)}</span>
          {sortBy === field ? sortComponent : ''}
        </div>
      );
    }
    return (
      <div style={inlineStylesHeaders[field]}>
        <span>{t(label)}</span>
      </div>
    );
  };
  const handleChangeTextField = (event) => {
    const { value } = event.target;
    setTextFieldValue(
      value
        .split('\n')
        .map((o) => o
          .split(',')
          .map((p) => p.split(';'))
          .flat())
        .flat()
        .join('\n'),
    );
  };
  const sort = R.sortWith(
    orderAsc ? [R.ascend(R.prop(sortBy))] : [R.descend(R.prop(sortBy))],
  );
  const sortedResolvedEntities = sortBy
    ? sort(resolvedEntities)
    : resolvedEntities;
  return (
    <div>
      <Typography variant="h1" gutterBottom={true} style={{ marginBottom: 18 }}>
        {t('Search for multiple entities')}
      </Typography>
      <Grid container={true} spacing={3}>
        <Grid item={true} xs={3}>
          <TextField
            onChange={handleChangeTextField}
            value={textFieldValue}
            multiline={true}
            fullWidth={true}
            minRows={12}
            placeholder={t('One keyword by line or separated by commas')}
            inputProps={{ style: { paddingTop: 20, lineHeight: '50px' } }}
          />
        </Grid>
        <Grid item={true} xs={9}>
          <Box style={{ width: '100%', marginTop: 2 }}>
            <LinearProgress
              variant={loading ? 'indeterminate' : 'determinate'}
              value={0}
            />
          </Box>
          <List classes={{ root: classes.linesContainer }}>
            <ListItem
              classes={{ root: classes.itemHead }}
              divider={false}
              style={{ paddingTop: 0 }}
            >
              <ListItemIcon>
                <span
                  style={{
                    padding: '0 8px 0 8px',
                    fontWeight: 700,
                    fontSize: 12,
                  }}
                >
                  #
                </span>
              </ListItemIcon>
              <ListItemText
                primary={
                  <div>
                    {SortHeader('type', 'Type', true)}
                    {SortHeader('value', 'Value', true)}
                    {SortHeader('labels', 'Labels', true)}
                    {SortHeader('author', 'Author', true)}
                    {SortHeader('creator', 'Creator', true)}
                    {SortHeader('reports', 'Reports', true)}
                    {SortHeader('updated_at', 'Modified', true)}
                  </div>
                }
              />
              <ListItemIcon classes={{ root: classes.goIcon }}>
                &nbsp;
              </ListItemIcon>
            </ListItem>
            {sortedResolvedEntities.map((entity) => {
              const inPlatform = entity.in_platform;
              const link = inPlatform && `${resolveLink(entity.type)}/${entity.id}`;
              return (
                <ListItem
                  key={entity.id}
                  classes={{ root: classes.item }}
                  divider={true}
                  button={inPlatform}
                  component={inPlatform && Link}
                  to={inPlatform && link}
                >
                  <ListItemIcon classes={{ root: classes.itemIcon }}>
                    <ItemIcon type={entity.type} />
                  </ListItemIcon>
                  <ListItemText
                    primary={
                      <div>
                        <div
                          className={classes.bodyItem}
                          style={inlineStyles.type}
                        >
                          {entity.in_platform ? (
                            <Chip
                              classes={{ root: classes.chip }}
                              variant="outlined"
                              color="primary"
                              label={t(`entity_${entity.type}`)}
                            />
                          ) : (
                            <Chip
                              classes={{ root: classes.chip }}
                              variant="outlined"
                              color="error"
                              label={t('Unknown')}
                            />
                          )}
                        </div>
                        <div
                          className={classes.bodyItem}
                          style={inlineStyles.value}
                        >
                          {entity.value}
                        </div>
                        <div
                          className={classes.bodyItem}
                          style={inlineStyles.labels}
                        >
                          {entity.in_platform && (
                            <StixCoreObjectLabels
                              variant="inList"
                              labels={entity.labels}
                            />
                          )}
                        </div>
                        <div
                          className={classes.bodyItem}
                          style={inlineStyles.author}
                        >
                          {entity.in_platform && entity.author}
                        </div>
                        <div
                          className={classes.bodyItem}
                          style={inlineStyles.creator}
                        >
                          {entity.in_platform && entity.creator}
                        </div>
                        <div
                          className={classes.bodyItem}
                          style={inlineStyles.reports}
                        >
                          {entity.in_platform && (
                            <Chip
                              classes={{ root: classes.chip }}
                              label={n(entity.reports.pageInfo.globalCount)}
                            />
                          )}
                        </div>
                        <div
                          className={classes.bodyItem}
                          style={inlineStyles.updated_at}
                        >
                          {entity.in_platform && nsd(entity.updated_at)}
                        </div>
                      </div>
                    }
                  />
                  <ListItemIcon classes={{ root: classes.goIcon }}>
                    {entity.in_platform && <KeyboardArrowRightOutlined />}
                  </ListItemIcon>
                </ListItem>
              );
            })}
          </List>
        </Grid>
      </Grid>
    </div>
  );
};

export default SearchBulk;
