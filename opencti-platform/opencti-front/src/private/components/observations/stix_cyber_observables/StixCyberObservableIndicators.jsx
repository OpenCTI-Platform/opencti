import React, { useRef, useState } from 'react';
import { createFragmentContainer, graphql } from 'react-relay';
import { Link } from 'react-router-dom';
import List from '@mui/material/List';
import ListItemIcon from '@mui/material/ListItemIcon';
import ListItemText from '@mui/material/ListItemText';
import Typography from '@mui/material/Typography';
import Dialog from '@mui/material/Dialog';
import DialogContent from '@mui/material/DialogContent';
import DialogContentText from '@mui/material/DialogContentText';
import DialogActions from '@mui/material/DialogActions';
import Menu from '@mui/material/Menu';
import MenuItem from '@mui/material/MenuItem';
import Button from '@common/button/Button';
import IconButton from '@common/button/IconButton';
import { Add } from '@mui/icons-material';
import { useTheme } from '@mui/styles';
import { ListItem, ListItemButton } from '@mui/material';
import { useFormatter } from '../../../../components/i18n';
import ItemIcon from '../../../../components/ItemIcon';
import StixCyberObservableAddIndicators from './StixCyberObservableAddIndicators';
import StixCyberObservableIndicatorPopover from './StixCyberObservableIndicatorPopover';
import Security from '../../../../utils/Security';
import { KNOWLEDGE_KNUPDATE } from '../../../../utils/hooks/useGranted';
import { commitMutation } from '../../../../relay/environment';
import ItemPatternType from '../../../../components/ItemPatternType';
import Transition from '../../../../components/Transition';
import { insertNode } from '../../../../utils/store';

const inlineStyles = {
  pattern_type: {
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
  bodyItem: {
    height: '100%',
    fontSize: 13,
  },
};

const stixCyberObservableIndicatorsPromoteMutation = graphql`
  mutation StixCyberObservableIndicatorsPromoteMutation(
    $id: ID!
  ) {
    stixCyberObservableEdit(id: $id) {
      promoteToIndicator {
        id
        entity_type
        parent_types
        name
        created_at
        updated_at
        pattern_type
      }
    }
  }
`;

const indicatorParams = { first: 200 };
const StixCyberObservableIndicatorsComponent = ({ stixCyberObservable }) => {
  const { t_i18n, fd } = useFormatter();
  const theme = useTheme();

  const [isAddOrCreateIndicatorsMenuOpen, setIsAddOrCreateIndicatorsMenuOpen] = useState(false);
  const [isCreateIndicatorMenuOpen, setIsCreateIndicatorMenuOpen] = useState(false);
  const [isAddIndicatorDrawerOpen, setIsAddIndicatorDrawerOpen] = useState(false);
  const [isCreatingIndicator, setIsCreatingIndicator] = useState(false);

  const AddOrCreateIndicatorsButtonRef = useRef(null);

  const handleOpenAddOrCreateIndicatorMenu = () => setIsAddOrCreateIndicatorsMenuOpen(true);
  const handleCloseAddOrCreateIndicatorMenu = () => setIsAddOrCreateIndicatorsMenuOpen(false);
  const handleOpenCreateIndicatorMenu = () => {
    setIsCreateIndicatorMenuOpen(true);
    setIsAddOrCreateIndicatorsMenuOpen(false);
  };
  const handleCloseCreateIndicatorMenu = () => setIsCreateIndicatorMenuOpen(false);
  const handleOpenAddIndicatorDrawer = () => {
    setIsAddIndicatorDrawerOpen(true);
    setIsAddOrCreateIndicatorsMenuOpen(false);
  };
  const handleCloseAddIndicatorDrawer = () => setIsAddIndicatorDrawerOpen(false);
  const submitPromoteStix = () => {
    setIsCreatingIndicator(true);
    commitMutation({
      mutation: stixCyberObservableIndicatorsPromoteMutation,
      variables: {
        ...indicatorParams,
        id: stixCyberObservable.id,
      },
      updater: (store) => {
        insertNode(
          store,
          'Pagination_stixCyberObservables_indicators',
          {},
          'stixCyberObservableEdit',
          stixCyberObservable.id,
          undefined,
          undefined,
          'promoteToIndicator',
        );
      },
      onCompleted: () => {
        setIsCreatingIndicator(false);
        handleCloseCreateIndicatorMenu();
      },
      onError: () => {
        setIsCreatingIndicator(false);
        handleCloseCreateIndicatorMenu();
      },
    });
  };

  return (
    <div>
      <Typography variant="h3" gutterBottom={true} style={{ float: 'left' }}>
        {t_i18n('Indicators composed with this observable')}
      </Typography>
      <Security needs={[KNOWLEDGE_KNUPDATE]}>
        <IconButton
          ref={AddOrCreateIndicatorsButtonRef}
          aria-label="Add or create indicators button"
          color="primary"
          onClick={handleOpenAddOrCreateIndicatorMenu}
          style={{ float: 'left', margin: '-15px 0 0 -2px' }}
        >
          <Add fontSize="small" />
        </IconButton>
        <Menu
          anchorEl={AddOrCreateIndicatorsButtonRef.current}
          open={isAddOrCreateIndicatorsMenuOpen}
          onClose={handleCloseAddOrCreateIndicatorMenu}
        >
          <MenuItem onClick={handleOpenCreateIndicatorMenu}>
            {t_i18n('Create')}
          </MenuItem>
          <MenuItem onClick={handleOpenAddIndicatorDrawer}>
            {t_i18n('Add')}
          </MenuItem>
        </Menu>
      </Security>
      <div className="clearfix" />
      <List style={{ marginTop: -15 }} aria-label="Stix cyber observable indicators list">
        {stixCyberObservable.indicators.edges.map((indicatorEdge) => (
          <ListItem
            key={indicatorEdge.node.id}
            divider={true}
            disablePadding
            secondaryAction={(
              <StixCyberObservableIndicatorPopover
                observableId={stixCyberObservable.id}
                indicatorId={indicatorEdge.node.id}
              />
            )}
          >
            <ListItemButton
              aria-label="stix cyber observable indicators item"
              style={{ paddingLeft: 10, height: 50 }}
              component={Link}
              to={`/dashboard/observations/indicators/${indicatorEdge.node.id}`}
            >
              <ListItemIcon style={{ color: theme.palette.primary.main }}>
                <ItemIcon type={indicatorEdge.node.entity_type} />
              </ListItemIcon>
              <ListItemText
                primary={(
                  <div>
                    <div style={{ ...inlineStyles.pattern_type, ...inlineStyles.bodyItem }}>
                      <ItemPatternType
                        label={indicatorEdge.node.pattern_type}
                        variant="inList"
                      />
                    </div>
                    <div style={{ ...inlineStyles.observable_value, ...inlineStyles.bodyItem }}>
                      {indicatorEdge.node.name}
                    </div>
                    <div style={{ ...inlineStyles.created_at, ...inlineStyles.bodyItem }}>
                      {fd(indicatorEdge.node.created_at)}
                    </div>
                  </div>
                )}
              />
            </ListItemButton>
          </ListItem>
        ))}
      </List>
      <Dialog
        open={isCreateIndicatorMenuOpen}
        slotProps={{ paper: { elevation: 1 } }}
        keepMounted={true}
        slots={{ transition: Transition }}
        onClose={handleCloseCreateIndicatorMenu}
      >
        <DialogContent>
          <DialogContentText>
            {t_i18n(
              'Do you want to create a STIX Indicator from this observable?',
            )}
          </DialogContentText>
        </DialogContent>
        <DialogActions>
          <Button
            variant="secondary"
            onClick={handleCloseCreateIndicatorMenu}
            disabled={isCreatingIndicator}
          >
            {t_i18n('Cancel')}
          </Button>
          <Button
            onClick={submitPromoteStix}
            disabled={isCreatingIndicator}
          >
            {t_i18n('Create')}
          </Button>
        </DialogActions>
      </Dialog>
      <StixCyberObservableAddIndicators
        open={isAddIndicatorDrawerOpen}
        handleClose={handleCloseAddIndicatorDrawer}
        stixCyberObservable={stixCyberObservable}
        stixCyberObservableIndicators={stixCyberObservable.indicators.edges}
      />
    </div>
  );
};

const StixCyberObservableIndicators = createFragmentContainer(
  StixCyberObservableIndicatorsComponent,
  {
    stixCyberObservable: graphql`
      fragment StixCyberObservableIndicators_stixCyberObservable on StixCyberObservable
      @argumentDefinitions(first: { type: "Int", defaultValue: 200 }) {
        id
        observable_value
        parent_types
        entity_type
        indicators(first: $first) @connection(key: "Pagination_stixCyberObservables_indicators") {
          edges {
            node {
              id
              entity_type
              parent_types
              name
              created_at
              updated_at
              pattern_type
            }
          }
        }
      }
    `,
  },
);

export default StixCyberObservableIndicators;
