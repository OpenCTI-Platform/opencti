import React, { useEffect, useState } from 'react';
import * as R from 'ramda';
import Grid from '@mui/material/Grid';
import TextField from '@mui/material/TextField';
import List from '@mui/material/List';
import ListItem from '@mui/material/ListItem';
import ListItemIcon from '@mui/material/ListItemIcon';
import ListItemText from '@mui/material/ListItemText';
import { ArrowDropDown, ArrowDropUp, FileDownloadOutlined, KeyboardArrowRightOutlined } from '@mui/icons-material';
import makeStyles from '@mui/styles/makeStyles';
import { Link } from 'react-router-dom';
import Chip from '@mui/material/Chip';
import Box from '@mui/material/Box';
import LinearProgress from '@mui/material/LinearProgress';
import { Subject, timer } from 'rxjs';
import { debounce } from 'rxjs/operators';
import ToggleButton from '@mui/material/ToggleButton';
import Tooltip from '@mui/material/Tooltip';
import { ToggleButtonGroup } from '@mui/material';
import ItemIcon from '../../components/ItemIcon';
import { searchStixCoreObjectsLinesSearchQuery } from './search/SearchStixCoreObjectsLines';
import { fetchQuery } from '../../relay/environment';
import { useFormatter } from '../../components/i18n';
import { getMainRepresentative } from '../../utils/defaultRepresentatives';
import { resolveLink } from '../../utils/Entity';
import StixCoreObjectLabels from './common/stix_core_objects/StixCoreObjectLabels';
import StixCoreObjectsExports from './common/stix_core_objects/StixCoreObjectsExports';
import useGranted, { KNOWLEDGE_KNGETEXPORT } from '../../utils/hooks/useGranted';
import { hexToRGB, itemColor } from '../../utils/Colors';
import ItemMarkings from '../../components/ItemMarkings';
import { export_max_size } from '../../utils/utils';
import Breadcrumbs from '../../components/Breadcrumbs';

const SEARCH$ = new Subject().pipe(debounce(() => timer(500)));

// Deprecated - https://mui.com/system/styles/basics/
// Do not use it for new code.
const useStyles = makeStyles((theme) => ({
  container: {
    transition: theme.transitions.create('padding', {
      easing: theme.transitions.easing.sharp,
      duration: theme.transitions.duration.leavingScreen,
    }),
    padding: '0 0 0 0',
  },
  gridContainer: {
    marginBottom: 20,
  },
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
  chip: {
    fontSize: 13,
    lineHeight: '12px',
    height: 20,
    textTransform: 'uppercase',
    borderRadius: 4,
    cursor: 'pointer',
    '&:hover': {
      backgroundColor: theme.palette.primary.main,
    },
  },
  chipNoLink: {
    fontSize: 13,
    lineHeight: '12px',
    height: 20,
    textTransform: 'uppercase',
    borderRadius: 4,
  },
  chipInList: {
    fontSize: 12,
    height: 20,
    float: 'left',
    width: 120,
    textTransform: 'uppercase',
    borderRadius: 4,
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
    width: '10%',
    fontSize: 12,
    fontWeight: '700',
    whiteSpace: 'nowrap',
    overflow: 'hidden',
    textOverflow: 'ellipsis',
    paddingRight: 10,
  },
  value: {
    float: 'left',
    width: '22%',
    fontSize: 12,
    fontWeight: '700',
    whiteSpace: 'nowrap',
    overflow: 'hidden',
    textOverflow: 'ellipsis',
    paddingRight: 10,
  },
  author: {
    float: 'left',
    width: '12%',
    fontSize: 12,
    fontWeight: '700',
    whiteSpace: 'nowrap',
    overflow: 'hidden',
    textOverflow: 'ellipsis',
    paddingRight: 10,
  },
  creator: {
    float: 'left',
    width: '12%',
    fontSize: 12,
    fontWeight: '700',
    whiteSpace: 'nowrap',
    overflow: 'hidden',
    textOverflow: 'ellipsis',
    paddingRight: 10,
  },
  labels: {
    float: 'left',
    width: '16%',
    fontSize: 12,
    fontWeight: '700',
    whiteSpace: 'nowrap',
    overflow: 'hidden',
    textOverflow: 'ellipsis',
    paddingRight: 10,
    cursor: 'default',
  },
  created_at: {
    float: 'left',
    width: '10%',
    fontSize: 12,
    fontWeight: '700',
    whiteSpace: 'nowrap',
    overflow: 'hidden',
    textOverflow: 'ellipsis',
    paddingRight: 10,
  },
  analyses: {
    float: 'left',
    width: '8%',
    fontSize: 12,
    fontWeight: '700',
    whiteSpace: 'nowrap',
    overflow: 'hidden',
    textOverflow: 'ellipsis',
    paddingRight: 10,
  },
  markings: {
    float: 'left',
    fontSize: 12,
    fontWeight: '700',
    whiteSpace: 'nowrap',
    overflow: 'hidden',
    textOverflow: 'ellipsis',
    paddingRight: 10,
  },
};

const inlineStyles = {
  type: {
    float: 'left',
    width: '10%',
    height: 20,
    whiteSpace: 'nowrap',
    overflow: 'hidden',
    textOverflow: 'ellipsis',
    paddingRight: 10,
  },
  value: {
    float: 'left',
    width: '22%',
    height: 20,
    whiteSpace: 'nowrap',
    overflow: 'hidden',
    textOverflow: 'ellipsis',
    paddingRight: 10,
  },
  author: {
    float: 'left',
    width: '12%',
    height: 20,
    whiteSpace: 'nowrap',
    overflow: 'hidden',
    textOverflow: 'ellipsis',
    paddingRight: 10,
  },
  creator: {
    float: 'left',
    width: '12%',
    height: 20,
    whiteSpace: 'nowrap',
    overflow: 'hidden',
    textOverflow: 'ellipsis',
    paddingRight: 10,
  },
  labels: {
    float: 'left',
    width: '16%',
    height: 20,
    whiteSpace: 'nowrap',
    overflow: 'hidden',
    textOverflow: 'ellipsis',
    paddingRight: 10,
  },
  created_at: {
    float: 'left',
    width: '10%',
    height: 20,
    whiteSpace: 'nowrap',
    overflow: 'hidden',
    textOverflow: 'ellipsis',
    paddingRight: 10,
  },
  analyses: {
    float: 'left',
    width: '8%',
    height: 20,
    whiteSpace: 'nowrap',
    overflow: 'hidden',
    textOverflow: 'ellipsis',
    paddingRight: 10,
  },
  markings: {
    float: 'left',
    height: 20,
    whiteSpace: 'nowrap',
    overflow: 'hidden',
    textOverflow: 'ellipsis',
    paddingRight: 10,
  },
};

const SearchBulk = () => {
  const { t_i18n, nsd, n } = useFormatter();
  const isGrantedToExports = useGranted([KNOWLEDGE_KNGETEXPORT]);
  const classes = useStyles();
  const [textFieldValue, setTextFieldValue] = useState('');
  const [resolvedEntities, setResolvedEntities] = useState([]);
  const [openExports, setOpenExports] = useState(false);
  const [sortBy, setSortBy] = useState(null);
  const [orderAsc, setOrderAsc] = useState(true);
  const [loading, setLoading] = useState(false);
  const [paginationOptions, setPaginationOptions] = useState({});
  const exportDisabled = resolvedEntities.length > export_max_size;
  useEffect(() => {
    const subscription = SEARCH$.subscribe({
      next: () => {
        const fetchData = async () => {
          const values = textFieldValue
            .split('\n')
            .filter((o) => o.length > 1)
            .map((val) => val.trim());
          if (values.length > 0) {
            setLoading(true);
            const searchPaginationOptions = {
              filters: {
                mode: 'and',
                filters: [
                  {
                    key: [
                      'name',
                      'aliases',
                      'x_opencti_aliases',
                      'x_mitre_id',
                      'value',
                      'subject',
                      'attribute_abstract',
                      'hashes.MD5',
                      'hashes.SHA-1',
                      'hashes.SHA-256',
                      'hashes.SHA-512',
                      'x_opencti_additional_names',
                    ],
                    values,
                  },
                ],
                filterGroups: [],
              },
              count: 5000,
            };
            const result = (
              await fetchQuery(
                searchStixCoreObjectsLinesSearchQuery,
                searchPaginationOptions,
              )
                .toPromise()
                .then((data) => {
                  const stixCoreObjectsEdges = data.stixCoreObjects.edges;
                  const stixCoreObjects = stixCoreObjectsEdges.map(
                    (o) => o.node,
                  );
                  return values.map((value) => {
                    const resolvedStixCoreObjects = stixCoreObjects.filter(
                      (o) => o.name?.toLowerCase() === value.toLowerCase()
                        || o.aliases
                          ?.map((p) => p.toLowerCase())
                          .includes(value.toLowerCase())
                        || o.x_opencti_aliases
                          ?.map((p) => p.toLowerCase())
                          .includes(value.toLowerCase())
                        || o.x_opencti_additional_names
                          ?.map((p) => p.toLowerCase())
                          .includes(value.toLowerCase())
                        || o.x_mitre_id?.toLowerCase() === value.toLowerCase()
                        || o.value?.toLowerCase() === value.toLowerCase()
                        || o.observable_value?.toLowerCase()
                          === value.toLowerCase()
                        || o.subject?.toLowerCase() === value.toLowerCase()
                        || o.abstract?.toLowerCase() === value.toLowerCase()
                        || o.hashes?.map((hash) => hash.hash.toLowerCase() === value.toLowerCase()),
                    );
                    if (resolvedStixCoreObjects.length > 0) {
                      return resolvedStixCoreObjects.map(
                        (resolvedStixCoreObject) => ({
                          id: resolvedStixCoreObject.id,
                          type: resolvedStixCoreObject.entity_type,
                          value: getMainRepresentative(resolvedStixCoreObject),
                          labels: resolvedStixCoreObject.objectLabel,
                          markings: resolvedStixCoreObject.objectMarking,
                          analyses: resolvedStixCoreObject.containersNumber.total,
                          created_at: resolvedStixCoreObject.created_at,
                          author: resolvedStixCoreObject.createdBy?.name ?? '-',
                          creators: (resolvedStixCoreObject.creators ?? [])
                            .map((c) => c?.name)
                            .join(', '),
                          in_platform: true,
                        }),
                      );
                    }
                    return [
                      {
                        id: value.trim(),
                        type: 'Unknown',
                        value: value.trim(),
                        in_platform: false,
                      },
                    ];
                  });
                })
            ).flat();
            const finalResult = R.uniqBy((o) => o.id, result);
            setLoading(false);
            setResolvedEntities(finalResult);
            setPaginationOptions(searchPaginationOptions);
          } else {
            setResolvedEntities([]);
          }
        };
        fetchData();
      },
    });
    return () => {
      subscription.unsubscribe();
    };
  });

  useEffect(() => {
    SEARCH$.next({ action: 'Search' });
  }, [textFieldValue, setResolvedEntities]);
  const reverseBy = (field) => {
    setSortBy(field);
    setOrderAsc((prevOrderAsc) => !prevOrderAsc);
    const newOrder = !orderAsc;
    const sort = (a, b) => {
      if (a[field] < b[field]) {
        return newOrder ? -1 : 1;
      } if (a[field] > b[field]) {
        return newOrder ? 1 : -1;
      }
      return 0;
    };
    setResolvedEntities(resolvedEntities.sort(sort));
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
          <span>{t_i18n(label)}</span>
          {sortBy === field ? sortComponent : ''}
        </div>
      );
    }
    return (
      <div style={inlineStylesHeaders[field]}>
        <span>{t_i18n(label)}</span>
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
  return (
    <>
      <Breadcrumbs variant="standard" elements={[{ label: t_i18n('Search') }, { label: t_i18n('Bulk search'), current: true }]} />
      <div className={classes.container}>
        <ToggleButtonGroup
          size="small"
          color="primary"
          style={{ float: 'right', marginTop: -5 }}
        >
          {!exportDisabled && (
            <ToggleButton
              value="export"
              aria-label="export"
              size="small"
              onClick={() => setOpenExports(true)}
            >
              <Tooltip title={t_i18n('Open export panel')}>
                <FileDownloadOutlined
                  fontSize="small"
                  color={openExports ? 'secondary' : 'primary'}
                />
              </Tooltip>
            </ToggleButton>
          )}
          {exportDisabled && (
            <Tooltip
              title={`${
                t_i18n(
                  'Export is disabled because too many entities are targeted (maximum number of entities is: ',
                ) + export_max_size
              })`}
            >
              <span>
                <ToggleButton
                  value="export"
                  aria-label="export"
                  size="small"
                  disabled={true}
                >
                  <FileDownloadOutlined fontSize="small" />
                </ToggleButton>
              </span>
            </Tooltip>
          )}
        </ToggleButtonGroup>
        <div className="clearfix" />
        {isGrantedToExports && (
          <StixCoreObjectsExports
            open={openExports}
            handleToggle={() => setOpenExports(!openExports)}
            paginationOptions={paginationOptions}
            exportContext={{ entity_type: 'Stix-Core-Object' }}
            variant="persistent"
          />
        )}
        <Grid
          container={true}
          spacing={3}
          classes={{ container: classes.gridContainer }}
        >
          <Grid item={true} xs={2} style={{ marginTop: -20 }}>
            <TextField
              onChange={handleChangeTextField}
              value={textFieldValue}
              multiline={true}
              fullWidth={true}
              minRows={20}
              placeholder={t_i18n('One keyword by line or separated by commas')}
              variant="outlined"
            />
          </Grid>
          <Grid item={true} xs={10} style={{ marginTop: -20 }}>
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
                      {SortHeader('author', 'Author', true)}
                      {SortHeader('creator', 'Creators', true)}
                      {SortHeader('labels', 'Labels', false)}
                      {SortHeader('created_at', 'Creation date', true)}
                      {SortHeader('analyses', 'Analyses', true)}
                      {SortHeader('markings', 'Markings', true)}
                    </div>
                }
                />
                <ListItemIcon classes={{ root: classes.goIcon }}>
                &nbsp;
                </ListItemIcon>
              </ListItem>
              {resolvedEntities.map((entity) => {
                const inPlatform = entity.in_platform;
                const link = inPlatform && `${resolveLink(entity.type)}/${entity.id}`;
                const linkAnalyses = `${link}/analyses`;
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
                        <>
                          <div
                            className={classes.bodyItem}
                            style={inlineStyles.type}
                          >
                            {entity.in_platform ? (
                              <Chip
                                classes={{ root: classes.chipInList }}
                                style={{
                                  backgroundColor: hexToRGB(
                                    itemColor(entity.type),
                                    0.08,
                                  ),
                                  color: itemColor(entity.type),
                                  border: `1px solid ${itemColor(entity.type)}`,
                                }}
                                label={t_i18n(`entity_${entity.type}`)}
                              />
                            ) : (
                              <Chip
                                classes={{ root: classes.chipInList }}
                                variant="outlined"
                                color="error"
                                label={t_i18n('Unknown')}
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
                            style={inlineStyles.author}
                          >
                            {entity.in_platform && entity.author}
                          </div>
                          <div
                            className={classes.bodyItem}
                            style={inlineStyles.creator}
                          >
                            {entity.in_platform && entity.creators}
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
                            style={inlineStyles.created_at}
                          >
                            {entity.in_platform && nsd(entity.created_at)}
                          </div>
                          <div
                            className={classes.bodyItem}
                            style={inlineStyles.analyses}
                          >
                            {entity.in_platform && (
                              <>
                                {[
                                  'Note',
                                  'Opinion',
                                  'Course-Of-Action',
                                  'Data-Component',
                                  'Data-Source',
                                ].includes(entity.type) ? (
                                  <Chip
                                    classes={{ root: classes.chipNoLink }}
                                    label={n(entity.analyses)}
                                  />
                                  ) : (
                                    <Chip
                                      classes={{ root: classes.chip }}
                                      label={n(entity.analyses)}
                                      component={Link}
                                      to={linkAnalyses}
                                    />
                                  )}
                              </>
                            )}
                          </div>
                          <div
                            className={classes.bodyItem}
                            style={inlineStyles.markings}
                          >
                            {entity.in_platform && (
                              <ItemMarkings
                                variant="inList"
                                markingDefinitions={entity.markings ?? []}
                                limit={1}
                              />
                            )}
                          </div>
                        </>
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
    </>
  );
};

export default SearchBulk;
