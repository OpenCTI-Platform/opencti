import React, { Component } from 'react';
import * as PropTypes from 'prop-types';
import { compose, map } from 'ramda';
import graphql from 'babel-plugin-relay/macro';
import { createFragmentContainer } from 'react-relay';
import { Link } from 'react-router-dom';
import { withStyles } from '@material-ui/core/styles';
import List from '@material-ui/core/List';
import ListItem from '@material-ui/core/ListItem';
import ListItemIcon from '@material-ui/core/ListItemIcon';
import ListItemText from '@material-ui/core/ListItemText';
import { Add, KeyboardArrowRight } from '@material-ui/icons';
import { ShieldSearch } from 'mdi-material-ui';
import Typography from '@material-ui/core/Typography';
import IconButton from '@material-ui/core/IconButton';
import Dialog from '@material-ui/core/Dialog';
import DialogContent from '@material-ui/core/DialogContent';
import DialogContentText from '@material-ui/core/DialogContentText';
import DialogActions from '@material-ui/core/DialogActions';
import Button from '@material-ui/core/Button';
import Slide from '@material-ui/core/Slide';
import Menu from '@material-ui/core/Menu';
import MenuItem from '@material-ui/core/MenuItem';
import ItemPatternType from '../../../../components/ItemPatternType';
import inject18n from '../../../../components/i18n';
import { commitMutation } from '../../../../relay/environment';

const styles = (theme) => ({
  paper: {
    height: '100%',
    minHeight: '100%',
    margin: '6px 0 0 0',
    padding: '15px 15px 15px 15px',
    borderRadius: 6,
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
});

const inlineStyles = {
  pattern_type: {
    float: 'left',
    width: '15%',
    height: 20,
    whiteSpace: 'nowrap',
    overflow: 'hidden',
    textOverflow: 'ellipsis',
  },
  name: {
    float: 'left',
    width: '50%',
    height: 20,
    whiteSpace: 'nowrap',
    overflow: 'hidden',
    textOverflow: 'ellipsis',
  },
  valid_from: {
    float: 'left',
    width: '15%',
    height: 20,
    whiteSpace: 'nowrap',
    overflow: 'hidden',
    textOverflow: 'ellipsis',
  },
  valid_until: {
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
      promotingStix: false,
    };
  }

  handleOpen(event) {
    this.setState({ anchorEl: event.currentTarget });
  }

  handleClose() {
    this.setState({ anchorEl: null });
  }

  handleOpenPromoteStix() {
    this.setState({ displayPromoteStix: true });
    this.handleClose();
  }

  handleClosePromoteStix() {
    this.setState({ displayPromoteStix: false });
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
    const {
      t, fd, classes, stixCyberObservable,
    } = this.props;
    const indicators = map((n) => n.node, stixCyberObservable.indicators.edges);
    return (
      <div style={{ height: '100%' }}>
        <Typography variant="h4" gutterBottom={true} style={{ float: 'left' }}>
          {t('Indicators composed with this observable')}
        </Typography>
        <IconButton
          color="secondary"
          aria-label="Label"
          onClick={this.handleOpen.bind(this)}
          style={{ float: 'left', margin: '-15px 0 0 -2px' }}
        >
          <Add fontSize="small" />
        </IconButton>
        <Menu
          anchorEl={this.state.anchorEl}
          open={Boolean(this.state.anchorEl)}
          onClose={this.handleClose.bind(this)}
          style={{ marginTop: 50 }}
        >
          <MenuItem onClick={this.handleOpenPromoteStix.bind(this)}>
            {t('[Promote] Create a STIX indicator')}
          </MenuItem>
        </Menu>
        <div className="clearfix" />
        <List style={{ marginTop: -10 }}>
          {indicators.map((indicator) => (
            <ListItem
              key={indicator.id}
              classes={{ root: classes.item }}
              divider={true}
              button={true}
              component={Link}
              to={`/dashboard/observations/indicators/${indicator.id}`}
            >
              <ListItemIcon classes={{ root: classes.itemIcon }}>
                <ShieldSearch />
              </ListItemIcon>
              <ListItemText
                primary={
                  <div>
                    <div
                      className={classes.bodyItem}
                      style={inlineStyles.pattern_type}
                    >
                      <ItemPatternType
                        variant="inList"
                        label={indicator.pattern_type}
                      />
                    </div>
                    <div className={classes.bodyItem} style={inlineStyles.name}>
                      {indicator.name}
                    </div>
                    <div
                      className={classes.bodyItem}
                      style={inlineStyles.valid_from}
                    >
                      {fd(indicator.valid_from)}
                    </div>
                    <div
                      className={classes.bodyItem}
                      style={inlineStyles.valid_until}
                    >
                      {fd(indicator.valid_until)}
                    </div>
                  </div>
                }
              />
              <ListItemIcon classes={{ root: classes.goIcon }}>
                <KeyboardArrowRight />
              </ListItemIcon>
            </ListItem>
          ))}
        </List>
        <Dialog
          open={this.state.displayPromoteStix}
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
              color="primary"
              disabled={this.state.promotingStix}
            >
              {t('Cancel')}
            </Button>
            <Button
              onClick={this.submitPromoteStix.bind(this)}
              color="primary"
              disabled={this.state.promotingStix}
            >
              {t('Create')}
            </Button>
          </DialogActions>
        </Dialog>
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
        indicators {
          edges {
            node {
              id
              name
              pattern_type
              valid_from
              valid_until
              x_opencti_score
              created
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
