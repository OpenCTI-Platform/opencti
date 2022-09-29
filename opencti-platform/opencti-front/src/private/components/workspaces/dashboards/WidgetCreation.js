import React, { Component } from 'react';
import * as PropTypes from 'prop-types';
import { v4 as uuid } from 'uuid';
import { compose } from 'ramda';
import { withStyles } from '@material-ui/core/styles';
import Dialog from '@material-ui/core/Dialog';
import DialogTitle from '@material-ui/core/DialogTitle';
import DialogContent from '@material-ui/core/DialogContent';
import DialogActions from '@material-ui/core/DialogActions';
import Stepper from '@material-ui/core/Stepper';
import Step from '@material-ui/core/Step';
import StepButton from '@material-ui/core/StepButton';
import StepLabel from '@material-ui/core/StepLabel';
import Slide from '@material-ui/core/Slide';
import Grid from '@material-ui/core/Grid';
import Typography from '@material-ui/core/Typography';
import Card from '@material-ui/core/Card';
import CardActionArea from '@material-ui/core/CardActionArea';
import CardContent from '@material-ui/core/CardContent';
import Button from '@material-ui/core/Button';
import { MapOutlined } from '@material-ui/icons';
import {
  FlaskOutline,
  FolderTableOutline,
  ChartTimeline,
  ChartAreasplineVariant,
  ChartBar,
  ChartDonut,
  AlignHorizontalLeft,
  DatabaseOutline,
  ViewListOutline,
} from 'mdi-material-ui';
import List from '@material-ui/core/List';
import ListItem from '@material-ui/core/ListItem';
import ListItemIcon from '@material-ui/core/ListItemIcon';
import ListItemText from '@material-ui/core/ListItemText';
import Markdown from 'react-markdown';
import Skeleton from '@material-ui/lab/Skeleton';
import remarkGfm from 'remark-gfm';
import remarkParse from 'remark-parse';
import { QueryRenderer } from '../../../../relay/environment';
import { stixDomainObjectsLinesSearchQuery } from '../../common/stix_domain_objects/StixDomainObjectsLines';
import inject18n from '../../../../components/i18n';
import ItemIcon from '../../../../components/ItemIcon';
import { truncate } from '../../../../utils/String';
import SearchInput from '../../../../components/SearchInput';

const Transition = React.forwardRef((props, ref) => (
  <Slide direction="up" ref={ref} {...props} />
));
Transition.displayName = 'TransitionSlide';

const styles = (theme) => ({
  createButton: {
    position: 'fixed',
    bottom: 30,
    right: 30,
    zIndex: 1001,
  },
  card: {
    backgroundColor: theme.palette.background.default,
    textAlign: 'center',
  },
  card2: {
    height: 100,
    backgroundColor: theme.palette.background.default,
  },
  card3: {
    height: 100,
    backgroundColor: theme.palette.background.default,
    textAlign: 'center',
  },
  cardAction: {
    height: 'max-content',
    paddingBottom: '2rem',
  },
  dialog: {
    height: 600,
  },
});

const HORIZONTAL_BAR = { key: 'horizontal-bar', name: 'Horizontal Bar' };
const DONUT = { key: 'donut', name: 'Donut' };
const AREA = { key: 'area', name: 'Area' };
const TIMELINE = { key: 'timeline', name: 'Timeline' };
const VERTICAL_BAR = { key: 'vertical-bar', name: 'Vertical Bar' };
const MAP = { key: 'map', name: 'Map' };
const LIST = { key: 'list', name: 'List' };

const visualizationTypesMapping = {
  all: [HORIZONTAL_BAR, DONUT, AREA, VERTICAL_BAR, TIMELINE, LIST],
  sectors: [HORIZONTAL_BAR, DONUT, AREA, VERTICAL_BAR, TIMELINE, LIST],
  countries: [MAP, HORIZONTAL_BAR, DONUT, AREA, VERTICAL_BAR, TIMELINE, LIST],
  'intrusion-sets': [HORIZONTAL_BAR, DONUT, AREA, VERTICAL_BAR, TIMELINE, LIST],
  malwares: [HORIZONTAL_BAR, DONUT, AREA, VERTICAL_BAR, TIMELINE, LIST],
  vulnerabilities: [HORIZONTAL_BAR, DONUT, VERTICAL_BAR, TIMELINE, LIST],
  campaigns: [AREA, TIMELINE, VERTICAL_BAR, LIST],
  incidents: [AREA, TIMELINE, VERTICAL_BAR, LIST],
  indicators: [HORIZONTAL_BAR, DONUT, VERTICAL_BAR, AREA, LIST],
  indicators_lifecycle: [HORIZONTAL_BAR, DONUT, VERTICAL_BAR, AREA, LIST],
  indicators_detection: [HORIZONTAL_BAR, DONUT, VERTICAL_BAR, AREA, LIST],
  reports: [HORIZONTAL_BAR, DONUT, VERTICAL_BAR, AREA, LIST],
};

const entityList = [
  {
    perspective: 'global_threats',
    data_type: [
      { name: 'Victimonlogy-All', value: 'all', description: 'Targeted entities' },
      { name: 'Victimology-Sector', value: 'sectors', description: 'Target sectors' },
      { name: 'Victimology-Regions', value: 'all', description: 'Targeted regions' },
      { name: 'Victimology-Countries', value: 'countries', description: 'Targeted countries' },
      { name: 'Activity-Intrusion Sets', value: 'intrusion-sets', description: '' },
      { name: 'Activity-Vulnerabilities', value: 'vulnerabilities', description: '' },
      { name: 'Activity-Reports', value: 'reports', description: 'Number of reports' },
      { name: 'Activity-Indicators', value: 'indicators', description: 'Number of indicators' },
      { name: 'Activity-Indicators Lifecycle', value: 'indicators_lifecycle', description: '' },
      { name: 'Activity-Indicators Detection', value: 'indicators_detection', description: '' },
      { name: 'Activity-all relationships', value: 'all', description: '' },
    ],
  },
  {
    perspective: 'global_assets',
    data_type: [
      { name: 'Total Inventory Items', value: 'all', description: '' },
      { name: 'Top-N most vulnerable inventory-items', value: 'all', description: '' },
      { name: 'Total Vulnerabilities by Year', value: 'all', description: '' },
      { name: 'Total Components', value: 'components', description: '' },
      { name: 'Activity-Intrusion Sets', value: 'intrusion-sets', description: '' },
      { name: 'Top-N most vulnerable components/products', value: 'all', description: '' },
    ],
  },
  {
    perspective: 'global_risks',
    data_type: [
      { name: "Total 'Active' Risks", value: 'active-risks', description: '' },
      { name: 'Top-N Risk Occurrences', value: 'all', description: '' },
      { name: 'Top-N Risks by severity', value: 'all', description: '' },
      { name: "Total 'Accpeted' Risks", value: 'accepted-risks', description: '' },
    ],
  },
  {
    perspective: 'threat',
    data_type: [
      { name: 'Victimonlogy-All', value: 'all', description: 'Targeted entries' },
      { name: 'Victimology-Sector', value: 'sectors', description: 'Targeted sectors' },
      { name: 'Victimology-Countries', value: 'countries', description: 'Targeted countries' },
      { name: 'Vulnerabilities', value: 'vulnerabilities', description: 'Targeted vulnerabilities' },
      { name: 'Activity-Campaigns', value: 'campaigns', description: 'Number of campaigns' },
      { name: 'Activity-Indicators', value: 'indicators', description: 'Number of indicators' },
      { name: 'Activity-Reports', value: 'reports', description: 'Number of reports' },
    ],
  },
  {
    perspective: 'threat',
    data_type: [
      { name: 'Victimonlogy-All', value: 'all', description: 'Targeted entries' },
      { name: 'Victimology-Sector', value: 'sectors', description: 'Targeted sectors' },
      { name: 'Victimology-Countries', value: 'countries', description: 'Targeted countries' },
      { name: 'Vulnerabilities', value: 'vulnerabilities', description: 'Targeted vulnerabilities' },
      { name: 'Activity-Campaigns', value: 'campaigns', description: 'Number of campaigns' },
      { name: 'Activity-Indicators', value: 'indicators', description: 'Number of indicators' },
      { name: 'Activity-Reports', value: 'reports', description: 'Number of reports' },
    ],
  },
  {
    perspective: 'identity',
    data_type: [
      { name: 'Threats-All', value: 'all', description: '' },
      { name: 'Threats-Intrusion Sets', value: 'intrusion-sets', description: '' },
      { name: 'Threats-Malwares', value: 'malwares', description: '' },
      { name: 'Activity-Campaigns', value: 'campaigns', description: 'Number of campaigns' },
      { name: 'Activity-Incidents', value: 'incidents', description: 'Number of indicators' },
      { name: 'Activity-Reports', value: 'reports', description: 'Number of reports' },
    ],
  },
  {
    perspective: 'asset_item',
    data_type: [],
  },
  {
    perspective: 'risk',
    data_type: [],
  },
];

class WidgetCreation extends Component {
  constructor(props) {
    super(props);
    this.state = {
      open: false,
      stepIndex: 0,
      keyword: '',
      perspective: null,
      selectedEntity: null,
      dataType: null,
      visualizationType: null,
    };
  }

  handleClose() {
    this.setState({
      stepIndex: 0,
      keyword: '',
      perspective: null,
      selectedEntity: null,
      dataType: null,
      visualizationType: null,
    });
  }

  handleSelectPerspective(perspective) {
    const avoidEntity = ['global_assets', 'global_risks'];
    this.setState({ perspective, stepIndex: avoidEntity.includes(perspective) ? 2 : 1 });
  }

  handleSelectEntity(stixDomainObject) {
    this.setState({ selectedEntity: stixDomainObject, stepIndex: 2 });
  }

  handleSelectDataType(dataType) {
    this.setState({ dataType, stepIndex: 3 });
  }

  handleSelectVisualizationType(visualizationType) {
    this.setState({ visualizationType }, () => this.completeSetup());
  }

  handleSetStep(stepIndex) {
    this.setState({ stepIndex });
  }

  handleSearch(searchTerm) {
    this.setState({ searchTerm });
  }

  completeSetup() {
    const {
      perspective, dataType, visualizationType, selectedEntity,
    } = this.state;
    this.props.onComplete({
      id: uuid(),
      perspective,
      dataType,
      visualizationType,
      entity: selectedEntity
        ? {
          id: selectedEntity.id,
          name: selectedEntity.name,
          type: selectedEntity.entity_type,
        }
        : null,
    });
    this.handleClose();
  }

  // eslint-disable-next-line class-methods-use-this
  renderIcon(visualizationType) {
    switch (visualizationType) {
      case 'map':
        return <MapOutlined fontSize="large" color="primary" />;
      case 'horizontal-bar':
        return <AlignHorizontalLeft fontSize="large" color="primary" />;
      case 'vertical-bar':
        return <ChartBar fontSize="large" color="primary" />;
      case 'donut':
        return <ChartDonut fontSize="large" color="primary" />;
      case 'area':
        return <ChartAreasplineVariant fontSize="large" color="primary" />;
      case 'timeline':
        return <ChartTimeline fontSize="large" color="primary" />;
      case 'list':
        return <ViewListOutline fontSize="large" color="primary" />;
      default:
        return 'Go away';
    }
  }

  renderEntities() {
    const { searchTerm, perspective } = this.state;
    let types = ['Threat-Actor', 'Intrusion-Set', 'Malware', 'Tool'];
    if (perspective === 'entity') {
      types = ['Identity', 'Location'];
    }
    return (
      <QueryRenderer
        query={stixDomainObjectsLinesSearchQuery}
        variables={{ count: 10, types, search: searchTerm }}
        render={({ props }) => {
          if (props && props.stixDomainObjects) {
            return (
              <List>
                {props.stixDomainObjects.edges.map((stixDomainObjectEdge) => (
                  <ListItem
                    key={stixDomainObjectEdge.node.id}
                    divider={true}
                    button={true}
                    onClick={this.handleSelectEntity.bind(
                      this,
                      stixDomainObjectEdge.node,
                    )}
                  >
                    <ListItemIcon>
                      <ItemIcon type={stixDomainObjectEdge.node.entity_type} />
                    </ListItemIcon>
                    <ListItemText
                      primary={stixDomainObjectEdge.node.name}
                      secondary={
                        <Markdown
                          remarkPlugins={[remarkGfm, remarkParse]}
                          parserOptions={{ commonmark: true }}
                          className="markdown"
                        >
                          {truncate(stixDomainObjectEdge.node.description, 200)}
                        </Markdown>
                      }
                    />
                  </ListItem>
                ))}
              </List>
            );
          }
          return (
            <List>
              {Array.from(Array(20), (e, i) => (
                <ListItem key={i} divider={true} button={false}>
                  <ListItemIcon>
                    <Skeleton
                      animation="wave"
                      variant="circle"
                      width={30}
                      height={30}
                    />
                  </ListItemIcon>
                  <ListItemText
                    primary={
                      <Skeleton
                        animation="wave"
                        variant="rect"
                        width="90%"
                        height={15}
                        style={{ marginBottom: 10 }}
                      />
                    }
                    secondary={
                      <Skeleton
                        animation="wave"
                        variant="rect"
                        width="90%"
                        height={15}
                      />
                    }
                  />
                </ListItem>
              ))}
            </List>
          );
        }}
      />
    );
  }

  renderGlobalDataTypes() {
    const { t, classes } = this.props;
    return (
      <Grid
        container={true}
        spacing={3}
        style={{ marginTop: 20, marginBottom: 20 }}
      >
        <Grid item={true} xs="4">
          <Card elevation={3} className={classes.card2}>
            <CardActionArea
              onClick={this.handleSelectDataType.bind(this, 'all')}
              style={{ height: '100%' }}
            >
              <CardContent>
                <Typography gutterBottom variant="h1" style={{ fontSize: 16 }}>
                  {t('Victimology - All')}
                </Typography>
                <br />
                <Typography variant="body1">
                  {t('Targeted entities')}
                </Typography>
              </CardContent>
            </CardActionArea>
          </Card>
        </Grid>
        <Grid item={true} xs="4">
          <Card elevation={3} className={classes.card2}>
            <CardActionArea
              onClick={this.handleSelectDataType.bind(this, 'sectors')}
              style={{ height: '100%' }}
            >
              <CardContent>
                <Typography gutterBottom variant="h1" style={{ fontSize: 16 }}>
                  {t('Victimology - Sectors')}
                </Typography>
                <br />
                <Typography variant="body1">{t('Targeted sectors')}</Typography>
              </CardContent>
            </CardActionArea>
          </Card>
        </Grid>
        <Grid item={true} xs="4">
          <Card elevation={3} className={classes.card2}>
            <CardActionArea
              onClick={this.handleSelectDataType.bind(this, 'countries')}
              style={{ height: '100%' }}
            >
              <CardContent>
                <Typography gutterBottom variant="h1" style={{ fontSize: 16 }}>
                  {t('Victimology - Countries')}
                </Typography>
                <br />
                <Typography variant="body1">
                  {t('Targeted countries')}
                </Typography>
              </CardContent>
            </CardActionArea>
          </Card>
        </Grid>
        <Grid item={true} xs="4">
          <Card elevation={3} className={classes.card2}>
            <CardActionArea
              onClick={this.handleSelectDataType.bind(this, 'intrusion-sets')}
              style={{ height: '100%' }}
            >
              <CardContent>
                <Typography gutterBottom variant="h1" style={{ fontSize: 16 }}>
                  {t('Activity - Intrusion Sets')}
                </Typography>
                <br />
                <Typography variant="body1">
                  {t('Based on ingested data')}
                </Typography>
              </CardContent>
            </CardActionArea>
          </Card>
        </Grid>
        <Grid item={true} xs="4">
          <Card elevation={3} className={classes.card2}>
            <CardActionArea
              onClick={this.handleSelectDataType.bind(this, 'malwares')}
              style={{ height: '100%' }}
            >
              <CardContent>
                <Typography gutterBottom variant="h1" style={{ fontSize: 16 }}>
                  {t('Activity - Malwares')}
                </Typography>
                <br />
                <Typography variant="body1">
                  {t('Based on ingested data')}
                </Typography>
              </CardContent>
            </CardActionArea>
          </Card>
        </Grid>
        <Grid item={true} xs="4">
          <Card elevation={3} className={classes.card2}>
            <CardActionArea
              onClick={this.handleSelectDataType.bind(this, 'vulnerabilities')}
              style={{ height: '100%' }}
            >
              <CardContent>
                <Typography gutterBottom variant="h1" style={{ fontSize: 16 }}>
                  {t('Activity - Vulnerabilities')}
                </Typography>
                <br />
                <Typography variant="body1">
                  {t('Based on ingested data')}
                </Typography>
              </CardContent>
            </CardActionArea>
          </Card>
        </Grid>
        <Grid item={true} xs="4">
          <Card elevation={3} className={classes.card2}>
            <CardActionArea
              onClick={this.handleSelectDataType.bind(this, 'reports')}
              style={{ height: '100%' }}
            >
              <CardContent>
                <Typography gutterBottom variant="h1" style={{ fontSize: 16 }}>
                  {t('Activity - Reports')}
                </Typography>
                <br />
                <Typography variant="body1">
                  {t('Number of reports')}
                </Typography>
              </CardContent>
            </CardActionArea>
          </Card>
        </Grid>
        <Grid item={true} xs="4">
          <Card elevation={3} className={classes.card2}>
            <CardActionArea
              onClick={this.handleSelectDataType.bind(this, 'indicators')}
              style={{ height: '100%' }}
            >
              <CardContent>
                <Typography gutterBottom variant="h1" style={{ fontSize: 16 }}>
                  {t('Activity - Indicators')}
                </Typography>
                <br />
                <Typography variant="body1">
                  {t('Number of indicators')}
                </Typography>
              </CardContent>
            </CardActionArea>
          </Card>
        </Grid>
        <Grid item={true} xs="4">
          <Card elevation={3} className={classes.card2}>
            <CardActionArea
              onClick={this.handleSelectDataType.bind(
                this,
                'indicators_lifecycle',
              )}
              style={{ height: '100%' }}
            >
              <CardContent>
                <Typography gutterBottom variant="h1" style={{ fontSize: 16 }}>
                  {t('Activity - Indicators lifecycle')}
                </Typography>
                <br />
                <Typography variant="body1">
                  {t('Number of revoked indicators')}
                </Typography>
              </CardContent>
            </CardActionArea>
          </Card>
        </Grid>
        <Grid item={true} xs="4">
          <Card elevation={3} className={classes.card2}>
            <CardActionArea
              onClick={this.handleSelectDataType.bind(
                this,
                'indicators_detection',
              )}
              style={{ height: '100%' }}
            >
              <CardContent>
                <Typography gutterBottom variant="h1" style={{ fontSize: 16 }}>
                  {t('Activity - Indicators detection')}
                </Typography>
                <br />
                <Typography variant="body1">
                  {t('Number of indicators with detection')}
                </Typography>
              </CardContent>
            </CardActionArea>
          </Card>
        </Grid>
      </Grid>
    );
  }

  renderThreatDataTypes() {
    const { t, classes } = this.props;
    return (
      <Grid
        container={true}
        spacing={3}
        style={{ marginTop: 20, marginBottom: 20 }}
      >
        <Grid item={true} xs="4">
          <Card elevation={3} className={classes.card2}>
            <CardActionArea
              onClick={this.handleSelectDataType.bind(this, 'all')}
              style={{ height: '100%' }}
            >
              <CardContent>
                <Typography gutterBottom variant="h1" style={{ fontSize: 16 }}>
                  {t('Victimology - All')}
                </Typography>
                <br />
                <Typography variant="body1">
                  {t('Targeted entities')}
                </Typography>
              </CardContent>
            </CardActionArea>
          </Card>
        </Grid>
        <Grid item={true} xs="4">
          <Card elevation={3} className={classes.card2}>
            <CardActionArea
              onClick={this.handleSelectDataType.bind(this, 'sectors')}
              style={{ height: '100%' }}
            >
              <CardContent>
                <Typography gutterBottom variant="h1" style={{ fontSize: 16 }}>
                  {t('Victimology - Sectors')}
                </Typography>
                <br />
                <Typography variant="body1">{t('Targeted sectors')}</Typography>
              </CardContent>
            </CardActionArea>
          </Card>
        </Grid>
        <Grid item={true} xs="4">
          <Card elevation={3} className={classes.card2}>
            <CardActionArea
              onClick={this.handleSelectDataType.bind(this, 'countries')}
              style={{ height: '100%' }}
            >
              <CardContent>
                <Typography gutterBottom variant="h1" style={{ fontSize: 16 }}>
                  {t('Victimology - Countries')}
                </Typography>
                <br />
                <Typography variant="body1">
                  {t('Targeted countries')}
                </Typography>
              </CardContent>
            </CardActionArea>
          </Card>
        </Grid>
        <Grid item={true} xs="4">
          <Card elevation={3} className={classes.card2}>
            <CardActionArea
              onClick={this.handleSelectDataType.bind(this, 'vulnerabilities')}
              style={{ height: '100%' }}
            >
              <CardContent>
                <Typography gutterBottom variant="h1" style={{ fontSize: 16 }}>
                  {t('Vulnerabilities')}
                </Typography>
                <br />
                <Typography variant="body1">
                  {t('Targeted vulnerabilities')}
                </Typography>
              </CardContent>
            </CardActionArea>
          </Card>
        </Grid>
        <Grid item={true} xs="4">
          <Card elevation={3} className={classes.card2}>
            <CardActionArea
              onClick={this.handleSelectDataType.bind(this, 'campaigns')}
              style={{ height: '100%' }}
            >
              <CardContent>
                <Typography gutterBottom variant="h1" style={{ fontSize: 16 }}>
                  {t('Activity - Campaigns')}
                </Typography>
                <br />
                <Typography variant="body1">
                  {t('Number of campaigns')}
                </Typography>
              </CardContent>
            </CardActionArea>
          </Card>
        </Grid>
        <Grid item={true} xs="4">
          <Card elevation={3} className={classes.card2}>
            <CardActionArea
              onClick={this.handleSelectDataType.bind(this, 'indicators')}
              style={{ height: '100%' }}
            >
              <CardContent>
                <Typography gutterBottom variant="h1" style={{ fontSize: 16 }}>
                  {t('Activity - Indicators')}
                </Typography>
                <br />
                <Typography variant="body1">
                  {t('Number of indicators')}
                </Typography>
              </CardContent>
            </CardActionArea>
          </Card>
        </Grid>
        <Grid item={true} xs="4">
          <Card elevation={3} className={classes.card2}>
            <CardActionArea
              onClick={this.handleSelectDataType.bind(this, 'reports')}
              style={{ height: '100%' }}
            >
              <CardContent>
                <Typography gutterBottom variant="h1" style={{ fontSize: 16 }}>
                  {t('Activity - Reports')}
                </Typography>
                <br />
                <Typography variant="body1">
                  {t('Number of reports')}
                </Typography>
              </CardContent>
            </CardActionArea>
          </Card>
        </Grid>
      </Grid>
    );
  }

  renderEntityDataTypes() {
    const { t, classes } = this.props;
    return (
      <Grid
        container={true}
        spacing={3}
        style={{ marginTop: 20, marginBottom: 20 }}
      >
        <Grid item={true} xs="4">
          <Card elevation={3} className={classes.card2}>
            <CardActionArea
              onClick={this.handleSelectDataType.bind(this, 'all')}
              style={{ height: '100%' }}
            >
              <CardContent>
                <Typography gutterBottom variant="h1" style={{ fontSize: 16 }}>
                  {t('Threats - All')}
                </Typography>
                <br />
                <Typography variant="body1">
                  {t('All threats targeting this entity')}
                </Typography>
              </CardContent>
            </CardActionArea>
          </Card>
        </Grid>
        <Grid item={true} xs="4">
          <Card elevation={3} className={classes.card2}>
            <CardActionArea
              onClick={this.handleSelectDataType.bind(this, 'intrusion-sets')}
              style={{ height: '100%' }}
            >
              <CardContent>
                <Typography gutterBottom variant="h1" style={{ fontSize: 16 }}>
                  {t('Threats - Intrusion Sets')}
                </Typography>
                <br />
                <Typography variant="body1">
                  {t('Intrusion Sets targeting this entity')}
                </Typography>
              </CardContent>
            </CardActionArea>
          </Card>
        </Grid>
        <Grid item={true} xs="4">
          <Card elevation={3} className={classes.card2}>
            <CardActionArea
              onClick={this.handleSelectDataType.bind(this, 'malwares')}
              style={{ height: '100%' }}
            >
              <CardContent>
                <Typography gutterBottom variant="h1" style={{ fontSize: 16 }}>
                  {t('Threats - Malwares')}
                </Typography>
                <br />
                <Typography variant="body1">
                  {t('All malwares targeting this entity')}
                </Typography>
              </CardContent>
            </CardActionArea>
          </Card>
        </Grid>
        <Grid item={true} xs="4">
          <Card elevation={3} className={classes.card2}>
            <CardActionArea
              onClick={this.handleSelectDataType.bind(this, 'campaigns')}
              style={{ height: '100%' }}
            >
              <CardContent>
                <Typography gutterBottom variant="h1" style={{ fontSize: 16 }}>
                  {t('Activity - Campaigns')}
                </Typography>
                <br />
                <Typography variant="body1">
                  {t('Number of campaigns')}
                </Typography>
              </CardContent>
            </CardActionArea>
          </Card>
        </Grid>
        <Grid item={true} xs="4">
          <Card elevation={3} className={classes.card2}>
            <CardActionArea
              onClick={this.handleSelectDataType.bind(this, 'incidents')}
              style={{ height: '100%' }}
            >
              <CardContent>
                <Typography gutterBottom variant="h1" style={{ fontSize: 16 }}>
                  {t('Activity - Incidents')}
                </Typography>
                <br />
                <Typography variant="body1">
                  {t('Number of incidents')}
                </Typography>
              </CardContent>
            </CardActionArea>
          </Card>
        </Grid>
        <Grid item={true} xs="4">
          <Card elevation={3} className={classes.card2}>
            <CardActionArea
              onClick={this.handleSelectDataType.bind(this, 'reports')}
              style={{ height: '100%' }}
            >
              <CardContent>
                <Typography gutterBottom variant="h1" style={{ fontSize: 16 }}>
                  {t('Activity - Reports')}
                </Typography>
                <br />
                <Typography variant="body1">
                  {t('Number of reports')}
                </Typography>
              </CardContent>
            </CardActionArea>
          </Card>
        </Grid>
      </Grid>
    );
  }

  renderVisualizationTypes() {
    const { t, classes } = this.props;
    const visualizationTypes = visualizationTypesMapping[this.state.dataType];
    return (
      <Grid
        container={true}
        spacing={3}
        style={{ marginTop: 20, marginBottom: 20 }}
      >
        {visualizationTypes.map((visualizationType) => (
          <Grid key={visualizationType.key} item={true} xs="4">
            <Card elevation={3} className={classes.card3}>
              <CardActionArea
                onClick={this.handleSelectVisualizationType.bind(
                  this,
                  visualizationType.key,
                )}
                style={{ height: '100%' }}
              >
                <CardContent>
                  {this.renderIcon(visualizationType.key)}
                  <Typography
                    gutterBottom
                    variant="body1"
                    style={{ marginTop: 8 }}
                  >
                    {t(visualizationType.name)}
                  </Typography>
                </CardContent>
              </CardActionArea>
            </Card>
          </Grid>
        ))}
      </Grid>
    );
  }

  getStepContent(stepIndex) {
    const { t, classes } = this.props;
    switch (stepIndex) {
      case 0:
        return (
          <Grid
            container={true}
            spacing={3}
            style={{ marginTop: 20, marginBottom: 20 }}
          >
            <Grid item={true} xs="4">
              <Card elevation={3} className={classes.card}>
                <CardActionArea
                  onClick={this.handleSelectPerspective.bind(this, 'global_threats')}
                  classes={{ root: classes.cardAction }}
                >
                  <CardContent>
                    <DatabaseOutline style={{ fontSize: 40 }} color="primary" />
                    <Typography
                      gutterBottom
                      variant="h1"
                      style={{ marginTop: 20 }}
                    >
                      {t('Global Threats')}
                    </Typography>
                    <br />
                    <Typography variant="body1">
                      {t(
                        'Display threat data without selecting a specific entity.',
                      )}
                    </Typography>
                  </CardContent>
                </CardActionArea>
              </Card>
            </Grid>
            <Grid item={true} xs="4">
              <Card elevation={3} className={classes.card}>
                <CardActionArea
                  onClick={this.handleSelectPerspective.bind(this, 'global_assets')}
                  classes={{ root: classes.cardAction }}
                >
                  <CardContent>
                    <DatabaseOutline style={{ fontSize: 40 }} color="primary" />
                    <Typography
                      gutterBottom
                      variant="h1"
                      style={{ marginTop: 20 }}
                    >
                      {t('Global Assets')}
                    </Typography>
                    <br />
                    <Typography variant="body1">
                      {t(
                        'Display asset data without selecting a specific entity.',
                      )}
                    </Typography>
                  </CardContent>
                </CardActionArea>
              </Card>
            </Grid>
            <Grid item={true} xs="4">
              <Card elevation={3} className={classes.card}>
                <CardActionArea
                  onClick={this.handleSelectPerspective.bind(this, 'global_risks')}
                  classes={{ root: classes.cardAction }}
                >
                  <CardContent>
                    <DatabaseOutline style={{ fontSize: 40 }} color="primary" />
                    <Typography
                      gutterBottom
                      variant="h1"
                      style={{ marginTop: 20 }}
                    >
                      {t('Global Risks')}
                    </Typography>
                    <br />
                    <Typography variant="body1">
                      {t(
                        'Display risk data without selecting a specific entity.',
                      )}
                    </Typography>
                  </CardContent>
                </CardActionArea>
              </Card>
            </Grid>
            <Grid item={true} xs="4">
              <Card elevation={3} className={classes.card}>
                <CardActionArea
                  onClick={this.handleSelectPerspective.bind(this, 'threat')}
                  classes={{ root: classes.cardAction }}
                >
                  <CardContent>
                    <FlaskOutline style={{ fontSize: 40 }} color="primary" />
                    <Typography
                      gutterBottom
                      variant="h1"
                      style={{ marginTop: 20 }}
                    >
                      {t('Threat Or Arsenal Item')}
                    </Typography>
                    <br />
                    <Typography variant="body1">
                      {t(
                        'Display data about intrusion sets, malwares, tools, etc.',
                      )}
                    </Typography>
                  </CardContent>
                </CardActionArea>
              </Card>
            </Grid>
            <Grid item={true} xs="4">
              <Card elevation={3} className={classes.card}>
                <CardActionArea
                  onClick={this.handleSelectPerspective.bind(this, 'identity')}
                  classes={{ root: classes.cardAction }}
                >
                  <CardContent>
                    <FolderTableOutline
                      style={{ fontSize: 40 }}
                      color="primary"
                    />
                    <Typography
                      gutterBottom
                      variant="h1"
                      style={{ marginTop: 20 }}
                    >
                      {t('Identity Or Location')}
                    </Typography>
                    <br />
                    <Typography variant="body1">
                      {t(
                        'Display data about organizations, sectors, countries, etc.',
                      )}
                    </Typography>
                  </CardContent>
                </CardActionArea>
              </Card>
            </Grid>
            <Grid item={true} xs="4">
              <Card elevation={3} className={classes.card}>
                <CardActionArea
                  onClick={this.handleSelectPerspective.bind(this, 'asset_item')}
                  classes={{ root: classes.cardAction }}
                >
                  <CardContent>
                    <FolderTableOutline
                      style={{ fontSize: 40 }}
                      color="primary"
                    />
                    <Typography
                      gutterBottom
                      variant="h1"
                      style={{ marginTop: 20 }}
                    >
                      {t('Asset Item')}
                    </Typography>
                    <br />
                    <Typography variant="body1">
                      {t(
                        'Display data about a specific Component, Inventory, Item, etc.',
                      )}
                    </Typography>
                  </CardContent>
                </CardActionArea>
              </Card>
            </Grid>
            <Grid item={true} xs="4">
              <Card elevation={3} className={classes.card}>
                <CardActionArea
                  onClick={this.handleSelectPerspective.bind(this, 'risk')}
                  classes={{ root: classes.cardAction }}
                >
                  <CardContent>
                    <FolderTableOutline
                      style={{ fontSize: 40 }}
                      color="primary"
                    />
                    <Typography
                      gutterBottom
                      variant="h1"
                      style={{ marginTop: 20 }}
                    >
                      {t('Risk Or Vulnerability Item')}
                    </Typography>
                    <br />
                    <Typography variant="body1">
                      {t(
                        'Display data about a specific Risk or Vulnerability.',
                      )}
                    </Typography>
                  </CardContent>
                </CardActionArea>
              </Card>
            </Grid>
          </Grid>
        );
      case 1:
        return (
          <div>
            <SearchInput
              keyword={this.state.searchTerm}
              onSubmit={this.handleSearch.bind(this)}
              fullWidth={true}
              variant="noAnimation"
            />
            {this.renderEntities()}
          </div>
        );
      case 2:
        return (
          // entityList
          // <div>
          //   {this.state.perspective === 'global_threats'
          //     && this.renderGlobalDataTypes()}
          //   {this.state.perspective === 'threat'
          //     && this.renderThreatDataTypes()}
          //   {this.state.perspective === 'entity'
          //     && this.renderEntityDataTypes()}
          // </div>
          <div>
            <Grid
              container={true}
              spacing={3}
              style={{ marginTop: 20, marginBottom: 20 }}
            >
              {(entityList
                .filter((value) => (value.perspective === this.state.perspective))[0].data_type)
                .map((entity, i) => (
                  <Grid key={i} item={true} xs="4">
                    <Card elevation={3} className={classes.card2}>
                      <CardActionArea
                        onClick={this.handleSelectDataType.bind(this, entity.value)}
                        style={{ height: '100%' }}
                      >
                        <CardContent>
                          <Typography gutterBottom variant="h1" style={{ fontSize: 16 }}>
                            {entity.name}
                          </Typography>
                          <br />
                          <Typography variant="body1">
                            {entity.description}
                          </Typography>
                        </CardContent>
                      </CardActionArea>
                    </Card>
                  </Grid>
                ))
              }
            </Grid>
          </div>
        );
      case 3:
        return <div>{this.renderVisualizationTypes()}</div>;
      default:
        return 'Go away!';
    }
  }

  render() {
    const { stepIndex } = this.state;
    const {
      t, open, handleWidgetCreation,
    } = this.props;
    return (
        <Dialog
          open={open}
          TransitionComponent={Transition}
          fullWidth={true}
          maxWidth="md"
        >
          <DialogTitle>
            <Stepper linear={false} activeStep={stepIndex}>
              <Step>
                <StepButton
                  onClick={this.handleSetStep.bind(this, 0)}
                  disabled={stepIndex === 0}
                >
                  <StepLabel>{t('Perspective')}</StepLabel>
                </StepButton>
              </Step>
              <Step>
                <StepButton
                  onClick={this.handleSetStep.bind(this, 1)}
                  disabled={
                    stepIndex <= 1 || this.state.perspective === 'global'
                  }
                >
                  <StepLabel>{t('Entity')}</StepLabel>
                </StepButton>
              </Step>
              <Step>
                <StepButton
                  onClick={this.handleSetStep.bind(this, 2)}
                  disabled={stepIndex <= 2}
                >
                  <StepLabel>{t('Data type')}</StepLabel>
                </StepButton>
              </Step>
              <Step>
                <StepButton
                  onClick={this.handleSetStep.bind(this, 3)}
                  disabled={stepIndex <= 3}
                >
                  <StepLabel>{t('Visualization')}</StepLabel>
                </StepButton>
              </Step>
            </Stepper>
          </DialogTitle>
          <DialogContent>{this.getStepContent(stepIndex)}</DialogContent>
          <DialogActions>
            <Button variant='outlined' onClick={() => handleWidgetCreation()}>{t('Cancel')}</Button>
          </DialogActions>
        </Dialog>
    );
  }
}

WidgetCreation.propTypes = {
  handleWidgetCreation: PropTypes.func,
  open: PropTypes.bool,
  onComplete: PropTypes.func,
  classes: PropTypes.object,
  theme: PropTypes.object,
  t: PropTypes.func,
};

export default compose(inject18n, withStyles(styles))(WidgetCreation);
