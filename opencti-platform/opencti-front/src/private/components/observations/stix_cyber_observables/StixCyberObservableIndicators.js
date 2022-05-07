import React, { Component } from 'react';
import * as PropTypes from 'prop-types';
import { compose, includes, filter, append } from 'ramda';
import { graphql, createFragmentContainer } from 'react-relay';
import { Link } from 'react-router-dom';
import withStyles from '@mui/styles/withStyles';
import List from '@mui/material/List';
import ListItem from '@mui/material/ListItem';
import ListItemIcon from '@mui/material/ListItemIcon';
import ListItemText from '@mui/material/ListItemText';
import ListItemSecondaryAction from '@mui/material/ListItemSecondaryAction';
import Typography from '@mui/material/Typography';
import Dialog from '@mui/material/Dialog';
import DialogContent from '@mui/material/DialogContent';
import DialogContentText from '@mui/material/DialogContentText';
import Slide from '@mui/material/Slide';
import DialogActions from '@mui/material/DialogActions';
import Menu from '@mui/material/Menu';
import MenuItem from '@mui/material/MenuItem';
import Button from '@mui/material/Button';
import IconButton from '@mui/material/IconButton';
import { Add } from '@mui/icons-material';
import inject18n from '../../../../components/i18n';
import ItemIcon from '../../../../components/ItemIcon';
import StixCyberObservableAddIndicators from './StixCyberObservableAddIndicators';
import StixCyberObservableIndicatorPopover from './StixCyberObservableIndicatorPopover';
import Security, { KNOWLEDGE_KNUPDATE } from '../../../../utils/Security';
import { commitMutation } from '../../../../relay/environment';

const styles = (theme) => ({
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
  createButton: {
    float: 'left',
    marginTop: -15,
  },
});

const inlineStyles = {
  entity_type: {
    float: 'left',
    width: '20%',
    height: 20,
    whiteSpace: 'nowrap',
    overflow: 'hidden',
    textOverflow: 'ellipsis',
  },
  observable_value: {
    float: 'left',
    width: '50%',
    height: 20,
    whiteSpace: 'nowrap',
    overflow: 'hidden',
    textOverflow: 'ellipsis',
  },
  created_at: {
    float: 'left',
    height: 20,
    whiteSpace: 'nowrap',
    overflow: 'hidden',
    textOverflow: 'ellipsis',
  },
};

const Transition = React.forwardRef((props, ref) => (
  <Slide direction="up" ref={ref} {...props} />
));
Transition.displayName = 'TransitionSlide';

const stixCyberObservableIndicatorsPromoteMutation = graphql`
  mutation StixCyberObservableIndicatorsPromoteMutation($id: ID!) {
    stixCyberObservableEdit(id: $id) {
      promote {
        id
        ...StixCyberObservableIndicators_stixCyberObservable
      }
    }
  }
`;

class StixCyberObservableIndicatorsComponent extends Component {
  constructor(props) {
    super(props);
    this.state = {
      anchorEl: null,
      displayPromoteStix: false,
      displayCreate: false,
      promotingStix: false,
      deleted: [],
    };
  }

  onDelete(id) {
    this.setState({ deleted: append(id, this.state.deleted) });
  }

  handleOpen(event) {
    this.setState({ anchorEl: event.currentTarget });
  }

  handleClose() {
    this.setState({ anchorEl: null });
  }

  handleOpenPromoteStix() {
    this.setState({ anchorEl: null, displayPromoteStix: true });
    this.handleClose();
  }

  handleClosePromoteStix() {
    this.setState({ displayPromoteStix: false });
  }

  handleOpenCreate() {
    this.setState({ anchorEl: null, displayCreate: true });
  }

  handleCloseCreate() {
    this.setState({ displayCreate: false });
  }

  submitPromoteStix() {
    this.setState({ promotingStix: true });
    commitMutation({
      mutation: stixCyberObservableIndicatorsPromoteMutation,
      variables: {
        id: this.props.stixCyberObservable.id,
      },
      onCompleted: () => {
        this.setState({ promotingStix: false });
        this.handleClosePromoteStix();
      },
    });
  }

  render() {
    const { displayCreate, anchorEl } = this.state;
    const { t, fd, classes, stixCyberObservable } = this.props;
    return (
      <div style={{ marginTop: 20 }}>
        <Typography variant="h3" gutterBottom={true} style={{ float: 'left' }}>
          {t('Indicators composed with this observable')}
        </Typography>
        <Security needs={[KNOWLEDGE_KNUPDATE]}>
          <IconButton
            color="secondary"
            aria-label="Label"
            onClick={this.handleOpen.bind(this)}
            style={{ float: 'left', margin: '-15px 0 0 -2px' }}
            size="large"
          >
            <Add fontSize="small" />
          </IconButton>
          <Menu
            anchorEl={anchorEl}
            open={Boolean(anchorEl)}
            onClose={this.handleClose.bind(this)}
          >
            <MenuItem onClick={this.handleOpenPromoteStix.bind(this)}>
              {t('Create')}
            </MenuItem>
            <MenuItem onClick={this.handleOpenCreate.bind(this)}>
              {t('Add')}
            </MenuItem>
          </Menu>
        </Security>
        <div className="clearfix" />
        <List style={{ marginTop: -15 }}>
          {filter(
            (n) => !includes(n.node.id, this.state.deleted),
            stixCyberObservable.indicators.edges,
          ).map((indicatorEdge) => (
            <ListItem
              key={indicatorEdge.node.id}
              classes={{ root: classes.item }}
              divider={true}
              button={true}
              component={Link}
              to={`/dashboard/observations/indicators/${indicatorEdge.node.id}`}
            >
              <ListItemIcon classes={{ root: classes.itemIcon }}>
                <ItemIcon type={indicatorEdge.node.entity_type} />
              </ListItemIcon>
              <ListItemText
                primary={
                  <div>
                    <div
                      className={classes.bodyItem}
                      style={inlineStyles.entity_type}
                    >
                      {t(`entity_${indicatorEdge.node.entity_type}`)}
                    </div>
                    <div
                      className={classes.bodyItem}
                      style={inlineStyles.observable_value}
                    >
                      {indicatorEdge.node.name}
                    </div>
                    <div
                      className={classes.bodyItem}
                      style={inlineStyles.created_at}
                    >
                      {fd(indicatorEdge.node.created_at)}
                    </div>
                  </div>
                }
              />
              <ListItemSecondaryAction>
                <StixCyberObservableIndicatorPopover
                  observableId={stixCyberObservable.id}
                  indicatorId={indicatorEdge.node.id}
                  onDelete={this.onDelete.bind(this, indicatorEdge.node.id)}
                />
              </ListItemSecondaryAction>
            </ListItem>
          ))}
        </List>
        <Dialog
          open={this.state.displayPromoteStix}
          PaperProps={{ elevation: 1 }}
          keepMounted={true}
          TransitionComponent={Transition}
          onClose={this.handleClosePromoteStix.bind(this)}
        >
          <DialogContent>
            <DialogContentText>
              {t('Do you want to create a STIX Indcator from this observable?')}
            </DialogContentText>
          </DialogContent>
          <DialogActions>
            <Button
              onClick={this.handleClosePromoteStix.bind(this)}
              disabled={this.state.promotingStix}
            >
              {t('Cancel')}
            </Button>
            <Button
              onClick={this.submitPromoteStix.bind(this)}
              color="secondary"
              disabled={this.state.promotingStix}
            >
              {t('Create')}
            </Button>
          </DialogActions>
        </Dialog>
        <StixCyberObservableAddIndicators
          open={displayCreate}
          handleClose={this.handleCloseCreate.bind(this)}
          stixCyberObservableId={stixCyberObservable.id}
          stixCyberObservableIndicators={stixCyberObservable.indicators.edges}
        />
      </div>
    );
  }
}

StixCyberObservableIndicatorsComponent.propTypes = {
  stixCyberObservable: PropTypes.object,
  classes: PropTypes.object,
  t: PropTypes.func,
  fd: PropTypes.func,
  history: PropTypes.object,
};

const StixCyberObservableIndicators = createFragmentContainer(
  StixCyberObservableIndicatorsComponent,
  {
    stixCyberObservable: graphql`
      fragment StixCyberObservableIndicators_stixCyberObservable on StixCyberObservable {
        id
        indicators(first: 200) @connection(key: "Pagination_indicators") {
          edges {
            node {
              id
              entity_type
              name
              created_at
              updated_at
            }
          }
        }
      }
    `,
  },
);

export default compose(
  inject18n,
  withStyles(styles),
)(StixCyberObservableIndicators);
