import React, { Component } from 'react';
import * as PropTypes from 'prop-types';
import { v4 as uuid } from 'uuid';
import { compose } from 'ramda';
import { withStyles } from '@material-ui/core/styles';
import DialogTitle from '@material-ui/core/DialogTitle';
import DialogContent from '@material-ui/core/DialogContent';
import DialogActions from '@material-ui/core/DialogActions';
import Stepper from '@material-ui/core/Stepper';
import Step from '@material-ui/core/Step';
import StepButton from '@material-ui/core/StepButton';
import StepLabel from '@material-ui/core/StepLabel';
import Grid from '@material-ui/core/Grid';
import Typography from '@material-ui/core/Typography';
import Card from '@material-ui/core/Card';
import CardActionArea from '@material-ui/core/CardActionArea';
import CardContent from '@material-ui/core/CardContent';
import Button from '@material-ui/core/Button';
import { MapOutlined } from '@material-ui/icons';
import {
  ChartTimeline,
  ChartAreasplineVariant,
  ChartBar,
  ChartDonut,
  AlignHorizontalLeft,
  ViewListOutline,
} from 'mdi-material-ui';
import ShowChart from '@material-ui/icons/ShowChart';
import Money from '@material-ui/icons/Money';
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
      queryType: null,
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
      queryType: null,
    });
    this.props.handleWidgetCreation();
  }

  handleSelectPerspective(perspective) {
    this.setState({ perspective, stepIndex: perspective.lifecycle_step === 'dataType' ? 2 : 1 });
  }

  handleSelectEntity(stixDomainObject) {
    this.setState({ selectedEntity: stixDomainObject, stepIndex: 2 });
  }

  handleSelectDataType(dataType) {
    this.setState({ dataType, stepIndex: 3 });
  }

  handleSelectVisualizationType(visualizationType, queryType) {
    this.setState({ visualizationType, queryType }, () => this.completeSetup());
  }

  handleSetStep(stepIndex) {
    this.setState({ stepIndex });
  }

  handleSearch(searchTerm) {
    this.setState({ searchTerm });
  }

  handleEntitySearch(entity) {
    this.setState({ selectedEntity: entity, dataType: entity.dataTypes, stepIndex: 2 });
  }

  completeSetup() {
    const {
      perspective, dataType, visualizationType, selectedEntity, queryType,
    } = this.state;
    this.props.onComplete({
      id: uuid(),
      perspective: perspective.perspectiveType,
      dataType: dataType.dataType,
      visualizationType,
      entity: selectedEntity
        ? {
          id: selectedEntity.id,
          name: selectedEntity.name,
        }
        : null,
      config: {
        queryType,
        name: dataType.name,
        variables: dataType.variables,
      },
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
      case 'line':
        return <ShowChart fontSize="large" color="primary" />;
      case 'count':
        return <Money fontSize="large" color="primary" />;
      default:
        return 'Go away';
    }
  }

  renderDataTypes() {
    const { perspective } = this.state;
    const { t, classes, wizardConfig } = this.props;
    if (perspective.lifecycle_step === 'dataType') {
      return (
        <div>
          <Grid
            container={true}
            spacing={3}
            style={{ marginTop: 20, marginBottom: 20 }}
          >
            {wizardConfig.dataTypes
              .filter((dataType) => perspective.dataTypes.includes(dataType.id))
              .map((data) => (
                <Grid key={data.id} item={true} xs="4">
                  <Card elevation={3} className={classes.card2}>
                    <CardActionArea
                      onClick={this.handleSelectDataType.bind(this, data)}
                      style={{ height: '100%' }}
                    >
                      <CardContent>
                        <Typography gutterBottom variant="h1" style={{ fontSize: 16 }}>
                          {data.name && t(data.name)}
                        </Typography>
                        <br />
                        <Typography variant="body1">
                          {data.description && t(data.description)}
                        </Typography>
                      </CardContent>
                    </CardActionArea>
                  </Card>
                </Grid>
              ))}
          </Grid>
        </div>
      );
    }
    return (
      <div>
      </div>
    );
  }

  renderEntities() {
    const { searchTerm, perspective } = this.state;
    return (
      <QueryRenderer
        query={stixDomainObjectsLinesSearchQuery}
        variables={{ count: 10, type: perspective.dataTypes, search: searchTerm }}
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

  renderVisualizationTypes() {
    const { t, classes, wizardConfig } = this.props;
    const dataTypeVisualizations = Object.keys(this.state.dataType.visualizations);
    return (
      <Grid
        container={true}
        spacing={3}
        style={{ marginTop: 20, marginBottom: 20 }}
      >
        {dataTypeVisualizations
          && dataTypeVisualizations.map((visualizationType, i) => (
            <Grid key={i} item={true} xs="4">
              <Card elevation={3} className={classes.card3}>
                <CardActionArea
                  onClick={this.handleSelectVisualizationType.bind(
                    this,
                    visualizationType,
                    this.state.dataType.visualizations[visualizationType],
                  )}
                  style={{ height: '100%' }}
                >
                  <CardContent>
                    {this.renderIcon(visualizationType)}
                    <Typography
                      gutterBottom
                      variant="body1"
                      style={{ marginTop: 8 }}
                    >
                      {wizardConfig.visualizationLabels[visualizationType]
                        && t(wizardConfig.visualizationLabels[visualizationType])}
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
    const { t, classes, wizardConfig } = this.props;
    const filteredPerspectives = wizardConfig.perspectives
      .filter((perspective) => perspective.visible);
    const filteredEntities = wizardConfig.entities
      .filter((entity) => entity.visible);
    switch (stepIndex) {
      case 0:
        return (
          <Grid
            container={true}
            spacing={3}
            style={{ marginTop: 20, marginBottom: 20 }}
          >
            {filteredPerspectives && filteredPerspectives.map((perspective) => (
              <Grid key={perspective.id} item={true} xs="4">
                <Card elevation={3} className={classes.card}>
                  <CardActionArea
                    onClick={this.handleSelectPerspective.bind(this, perspective)}
                    classes={{ root: classes.cardAction }}
                  >
                    <CardContent>
                      <ItemIcon type={perspective.perspectiveType} />
                      <Typography
                        gutterBottom
                        variant="h1"
                        style={{ marginTop: 20 }}
                      >
                        {perspective.name && t(perspective.name)}
                      </Typography>
                      <br />
                      <Typography variant="body1">
                        {perspective.description && t(perspective.description)}
                      </Typography>
                    </CardContent>
                  </CardActionArea>
                </Card>
              </Grid>
            ))}
          </Grid>
        );
      case 1:
        return (
          <div>
            <List
              style={{ margin: '20px 0' }}
            >
              {filteredEntities && filteredEntities.map((entity) => (
                <ListItem
                  key={entity.id}
                  divider={true}
                  button={true}
                  onClick={this.handleEntitySearch.bind(this, entity)}
                >
                  <ListItemIcon>
                    <ItemIcon variant='inline' type='inventory_item' />
                  </ListItemIcon>
                  <ListItemText
                    primary={entity.name}
                    secondary={
                      <Markdown
                        remarkPlugins={[remarkGfm, remarkParse]}
                        parserOptions={{ commonmark: true }}
                        className="markdown"
                      >
                        {truncate(entity.description, 200)}
                      </Markdown>
                    }
                  />
                </ListItem>
              ))}
            </List>
            {/* <SearchInput
              keyword={this.state.searchTerm}
              onSubmit={this.handleSearch.bind(this)}
              fullWidth={true}
              variant="noAnimation"
            />
            {this.renderEntities()} */}
          </div>
        );
      case 2:
        return this.renderDataTypes();
      case 3:
        return <div>{this.renderVisualizationTypes()}</div>;
      default:
        return 'Go away!';
    }
  }

  render() {
    const { stepIndex } = this.state;
    const {
      t, handleWidgetCreation, wizardConfig,
    } = this.props;
    return (
      <>
        <DialogTitle>
          <Stepper linear={false} activeStep={stepIndex}>
            {wizardConfig.lifecycle && wizardConfig.lifecycle.map((data, i) => (
              <Step key={data.key}>
                <StepButton
                  onClick={this.handleSetStep.bind(this, data.ordinal)}
                  disabled={stepIndex !== i && data.ordinal !== 0}
                >
                  <StepLabel>{data.name && t(data.name)}</StepLabel>
                </StepButton>
              </Step>
            ))}
          </Stepper>
        </DialogTitle>
        <DialogContent>{this.getStepContent(stepIndex)}</DialogContent>
        <DialogActions>
          <Button variant='outlined' onClick={() => handleWidgetCreation()}>{t('Cancel')}</Button>
        </DialogActions>
      </>
    );
  }
}

WidgetCreation.propTypes = {
  handleWidgetCreation: PropTypes.func,
  wizardConfig: PropTypes.object,
  open: PropTypes.bool,
  onComplete: PropTypes.func,
  classes: PropTypes.object,
  theme: PropTypes.object,
  t: PropTypes.func,
};

export default compose(inject18n, withStyles(styles))(WidgetCreation);
