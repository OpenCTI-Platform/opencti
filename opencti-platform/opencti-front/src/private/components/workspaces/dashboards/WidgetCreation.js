import React, { Component } from 'react';
import * as PropTypes from 'prop-types';
import { v4 as uuid } from 'uuid';
import { compose } from 'ramda';
import withStyles from '@mui/styles/withStyles';
import Dialog from '@mui/material/Dialog';
import DialogTitle from '@mui/material/DialogTitle';
import DialogContent from '@mui/material/DialogContent';
import DialogActions from '@mui/material/DialogActions';
import Stepper from '@mui/material/Stepper';
import Step from '@mui/material/Step';
import StepButton from '@mui/material/StepButton';
import StepLabel from '@mui/material/StepLabel';
import Slide from '@mui/material/Slide';
import Grid from '@mui/material/Grid';
import Typography from '@mui/material/Typography';
import Card from '@mui/material/Card';
import CardActionArea from '@mui/material/CardActionArea';
import CardContent from '@mui/material/CardContent';
import Button from '@mui/material/Button';
import Fab from '@mui/material/Fab';
import { Add, MapOutlined } from '@mui/icons-material';
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
import List from '@mui/material/List';
import ListItem from '@mui/material/ListItem';
import ListItemIcon from '@mui/material/ListItemIcon';
import ListItemText from '@mui/material/ListItemText';
import Markdown from 'react-markdown';
import Skeleton from '@mui/material/Skeleton';
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
    height: 180,
    backgroundColor: theme.palette.background.paperLight,
    textAlign: 'center',
  },
  card2: {
    height: 100,
    backgroundColor: theme.palette.background.paperLight,
  },
  card3: {
    height: 100,
    backgroundColor: theme.palette.background.paperLight,
    textAlign: 'center',
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
  regions: [HORIZONTAL_BAR, DONUT, AREA, VERTICAL_BAR, TIMELINE, LIST],
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
  relationships_list: [LIST],
};

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

  handleOpen() {
    this.setState({ open: true });
  }

  handleClose() {
    this.setState({
      open: false,
      stepIndex: 0,
      keyword: '',
      perspective: null,
      selectedEntity: null,
      dataType: null,
      visualizationType: null,
    });
  }

  handleSelectPerspective(perspective) {
    this.setState({ perspective, stepIndex: perspective === 'global' ? 2 : 1 });
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
    const { perspective, dataType, visualizationType, selectedEntity } = this.state;
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
                      variant="circular"
                      width={30}
                      height={30}
                    />
                  </ListItemIcon>
                  <ListItemText
                    primary={
                      <Skeleton
                        animation="wave"
                        variant="rectangular"
                        width="90%"
                        height={15}
                        style={{ marginBottom: 10 }}
                      />
                    }
                    secondary={
                      <Skeleton
                        animation="wave"
                        variant="rectangular"
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
          <Card variant="outlined" className={classes.card2}>
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
          <Card variant="outlined" className={classes.card2}>
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
          <Card variant="outlined" className={classes.card2}>
            <CardActionArea
              onClick={this.handleSelectDataType.bind(this, 'regions')}
              style={{ height: '100%' }}
            >
              <CardContent>
                <Typography gutterBottom variant="h1" style={{ fontSize: 16 }}>
                  {t('Victimology - Regions')}
                </Typography>
                <br />
                <Typography variant="body1">{t('Targeted regions')}</Typography>
              </CardContent>
            </CardActionArea>
          </Card>
        </Grid>
        <Grid item={true} xs="4">
          <Card variant="outlined" className={classes.card2}>
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
          <Card variant="outlined" className={classes.card2}>
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
          <Card variant="outlined" className={classes.card2}>
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
          <Card variant="outlined" className={classes.card2}>
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
          <Card variant="outlined" className={classes.card2}>
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
          <Card variant="outlined" className={classes.card2}>
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
          <Card variant="outlined" className={classes.card2}>
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
          <Card variant="outlined" className={classes.card2}>
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
        <Grid item={true} xs="4">
          <Card variant="outlined" className={classes.card2}>
            <CardActionArea
              onClick={this.handleSelectDataType.bind(
                this,
                'relationships_list',
              )}
              style={{ height: '100%' }}
            >
              <CardContent>
                <Typography gutterBottom variant="h1" style={{ fontSize: 16 }}>
                  {t('Activity - All relationships')}
                </Typography>
                <br />
                <Typography variant="body1">
                  {t('List of relationships with filters')}
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
          <Card variant="outlined" className={classes.card2}>
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
          <Card variant="outlined" className={classes.card2}>
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
          <Card variant="outlined" className={classes.card2}>
            <CardActionArea
              onClick={this.handleSelectDataType.bind(this, 'regions')}
              style={{ height: '100%' }}
            >
              <CardContent>
                <Typography gutterBottom variant="h1" style={{ fontSize: 16 }}>
                  {t('Victimology - Regions')}
                </Typography>
                <br />
                <Typography variant="body1">{t('Targeted regions')}</Typography>
              </CardContent>
            </CardActionArea>
          </Card>
        </Grid>
        <Grid item={true} xs="4">
          <Card variant="outlined" className={classes.card2}>
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
          <Card variant="outlined" className={classes.card2}>
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
          <Card variant="outlined" className={classes.card2}>
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
          <Card variant="outlined" className={classes.card2}>
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
          <Card variant="outlined" className={classes.card2}>
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
          <Card variant="outlined" className={classes.card2}>
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
          <Card variant="outlined" className={classes.card2}>
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
          <Card variant="outlined" className={classes.card2}>
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
          <Card variant="outlined" className={classes.card2}>
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
          <Card variant="outlined" className={classes.card2}>
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
          <Card variant="outlined" className={classes.card2}>
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
            <Card variant="outlined" className={classes.card3}>
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
              <Card variant="outlined" className={classes.card}>
                <CardActionArea
                  onClick={this.handleSelectPerspective.bind(this, 'global')}
                  style={{ height: '100%' }}
                >
                  <CardContent>
                    <DatabaseOutline style={{ fontSize: 40 }} color="primary" />
                    <Typography
                      gutterBottom
                      variant="h2"
                      style={{ marginTop: 20 }}
                    >
                      {t('Global')}
                    </Typography>
                    <br />
                    <Typography variant="body1">
                      {t(
                        'Display global data without selecting a specific entity.',
                      )}
                    </Typography>
                  </CardContent>
                </CardActionArea>
              </Card>
            </Grid>
            <Grid item={true} xs="4">
              <Card variant="outlined" className={classes.card}>
                <CardActionArea
                  onClick={this.handleSelectPerspective.bind(this, 'threat')}
                  style={{ height: '100%' }}
                >
                  <CardContent>
                    <FlaskOutline style={{ fontSize: 40 }} color="primary" />
                    <Typography
                      gutterBottom
                      variant="h2"
                      style={{ marginTop: 20 }}
                    >
                      {t('Threat or arsenal item')}
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
              <Card variant="outlined" className={classes.card}>
                <CardActionArea
                  onClick={this.handleSelectPerspective.bind(this, 'entity')}
                  style={{ height: '100%' }}
                >
                  <CardContent>
                    <FolderTableOutline
                      style={{ fontSize: 40 }}
                      color="primary"
                    />
                    <Typography
                      gutterBottom
                      variant="h2"
                      style={{ marginTop: 20 }}
                    >
                      {t('Identity or location')}
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
          </Grid>
        );
      case 1:
        return (
          <div style={{ paddingTop: 5 }}>
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
          <div>
            {this.state.perspective === 'global'
              && this.renderGlobalDataTypes()}
            {this.state.perspective === 'threat'
              && this.renderThreatDataTypes()}
            {this.state.perspective === 'entity'
              && this.renderEntityDataTypes()}
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
    const { t, classes } = this.props;
    return (
      <div>
        <Fab
          onClick={this.handleOpen.bind(this)}
          color="secondary"
          aria-label="Add"
          className={classes.createButton}
        >
          <Add />
        </Fab>
        <Dialog
          open={this.state.open}
          PaperProps={{ elevation: 1 }}
          TransitionComponent={Transition}
          onClose={this.handleClose.bind(this)}
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
            <Button onClick={this.handleClose.bind(this)}>{t('Cancel')}</Button>
          </DialogActions>
        </Dialog>
      </div>
    );
  }
}

WidgetCreation.propTypes = {
  onComplete: PropTypes.func,
  classes: PropTypes.object,
  theme: PropTypes.object,
  t: PropTypes.func,
};

export default compose(inject18n, withStyles(styles))(WidgetCreation);
