import React, { Component } from 'react';
import * as PropTypes from 'prop-types';
import { compose, map } from 'ramda';
import { graphql, createFragmentContainer } from 'react-relay';
import { Link } from 'react-router-dom';
import withStyles from '@mui/styles/withStyles';
import List from '@mui/material/List';
import ListItem from '@mui/material/ListItem';
import ListItemIcon from '@mui/material/ListItemIcon';
import ListItemText from '@mui/material/ListItemText';
import { Add, KeyboardArrowRight } from '@mui/icons-material';
import { ShieldSearch } from 'mdi-material-ui';
import Typography from '@mui/material/Typography';
import IconButton from '@mui/material/IconButton';
import Dialog from '@mui/material/Dialog';
import DialogContent from '@mui/material/DialogContent';
import DialogContentText from '@mui/material/DialogContentText';
import DialogActions from '@mui/material/DialogActions';
import Button from '@mui/material/Button';
import Slide from '@mui/material/Slide';
import Menu from '@mui/material/Menu';
import MenuItem from '@mui/material/MenuItem';
import Paper from '@mui/material/Paper';
import ItemPatternType from '../../../../components/ItemPatternType';
import inject18n from '../../../../components/i18n';
import { commitMutation } from '../../../../relay/environment';
import Security, { KNOWLEDGE_KNUPDATE } from '../../../../utils/Security';

const styles = (theme) => ({
  paper: {
    height: '100%',
    minHeight: '100%',
    margin: 0,
    padding: '25px 15px 15px 15px',
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
    const { t, fd, classes, stixCyberObservable } = this.props;
    const indicators = map((n) => n.node, stixCyberObservable.indicators.edges);
    return (
      <div style={{ height: '100%' }}>
        <Typography variant="h4" gutterBottom={true} style={{ float: 'left' }}>
          {t('Indicators composed with this observable')}
        </Typography>
        <Security
          needs={[KNOWLEDGE_KNUPDATE]}
          placeholder={<div style={{ height: 29 }} />}
        >
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
            anchorEl={this.state.anchorEl}
            open={Boolean(this.state.anchorEl)}
            onClose={this.handleClose.bind(this)}
          >
            <MenuItem onClick={this.handleOpenPromoteStix.bind(this)}>
              {t('[Promote] Create a STIX indicator')}
            </MenuItem>
          </Menu>
        </Security>
        <div className="clearfix" />
        <Paper classes={{ root: classes.paper }} variant="outlined">
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
                      <div
                        className={classes.bodyItem}
                        style={inlineStyles.name}
                      >
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
            PaperProps={{ elevation: 1 }}
            keepMounted={true}
            TransitionComponent={Transition}
            onClose={this.handleClosePromoteStix.bind(this)}
          >
            <DialogContent>
              <DialogContentText>
                {t(
                  'Do you want to create a STIX Indcator from this observable?',
                )}
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
        </Paper>
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
