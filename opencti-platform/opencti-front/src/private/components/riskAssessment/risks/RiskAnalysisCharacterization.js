import React, { Component } from 'react';
import * as PropTypes from 'prop-types';
import { compose, propOr, map } from 'ramda';
import { createFragmentContainer } from 'react-relay';
import graphql from 'babel-plugin-relay/macro';
import { withStyles } from '@material-ui/core/styles';
import Paper from '@material-ui/core/Paper';
import Table from '@material-ui/core/Table';
import TableBody from '@material-ui/core/TableBody';
import TableCell from '@material-ui/core/TableCell';
import LaunchIcon from '@material-ui/icons/Launch';
import TableContainer from '@material-ui/core/TableContainer';
import TableHead from '@material-ui/core/TableHead';
import TableRow from '@material-ui/core/TableRow';
import Grid from '@material-ui/core/Grid';
import Badge from '@material-ui/core/Badge';
import Avatar from '@material-ui/core/Avatar';
import Chip from '@material-ui/core/Chip';
import { InformationOutline, Information } from 'mdi-material-ui';
import Tooltip from '@material-ui/core/Tooltip';
import Typography from '@material-ui/core/Typography';
import inject18n from '../../../../components/i18n';
import ItemAuthor from '../../../../components/ItemAuthor';
import ItemMarking from '../../../../components/ItemMarking';
import ExpandableMarkdown from '../../../../components/ExpandableMarkdown';

const styles = (theme) => ({
  paper: {
    height: '100%',
    minHeight: '100%',
    margin: '10px 0 0 0',
    padding: '24px 24px 32px 24px',
    borderRadius: 6,
  },
  tableItem: {
    display: 'flex',
    alignItems: 'center',
    color: theme.palette.secondary.main,
    padding: '16.5px 16px',
    cursor: 'pointer',
  },
});

class RiskAnalysisCharacterizationComponent extends Component {
  render() {
    const {
      t, fldt, classes, risk,
    } = this.props;
    return (
      <div style={{ height: '100%' }} className="break">
         <Typography variant="h4" gutterBottom={true}>
          {t('Characterization')}
        </Typography>
      {/*  <Paper classes={{ root: classes.paper }} elevation={2}>
          <Typography variant="h3" gutterBottom={true}>
            {t('Marking')}
          </Typography>
          {risk.objectMarking.edges.length > 0 ? (
            map(
              (markingDefinition) => (
                <ItemMarking
                  key={markingDefinition.node.id}
                  label={markingDefinition.node.definition}
                  color={markingDefinition.node.x_opencti_color}
                />
              ),
              risk.objectMarking.edges,
            )
          ) : (
            <ItemMarking label="TLP:WHITE" />
          )}
          <Typography
            variant="h3"
            gutterBottom={true}
            style={{ marginTop: 20 }}
          >
            {t('Creation date')}
          </Typography>
          {fldt(risk.created)}
          <Typography
            variant="h3"
            gutterBottom={true}
            style={{ marginTop: 20 }}
          >
            {t('Modification date')}
          </Typography>
          {fldt(risk.modified)}
          <Typography
            variant="h3"
            gutterBottom={true}
            style={{ marginTop: 20 }}
          >
            {t('Author')}
          </Typography>
          <ItemAuthor createdBy={propOr(null, 'createdBy', risk)} />
          <Typography
            variant="h3"
            gutterBottom={true}
            style={{ marginTop: 20 }}
          >
            {t('Description')}
          </Typography>
          <ExpandableMarkdown
            className="markdown"
            source={risk.description}
            limit={250}
          />
        </Paper> */}
        <Paper classes={{ root: classes.paper }} elevation={2}>
            <TableContainer>
              <Table sx={{ minWidth: 650 }} aria-label="simple table">
                <TableHead>
                  <TableRow style={{ borderBottom: '1px solid white' }}>
                    <TableCell align="left">{t('Name')}</TableCell>
                    <TableCell align="left">{t('value')}</TableCell>
                    <TableCell align="left">{t('Detection Source')}</TableCell>
                  </TableRow>
                </TableHead>
                <TableBody>
                    <TableRow
                      sx={{ '&:last-child td, &:last-child th': { border: 0 } }}
                    >
                      <TableCell align="left">{t('Lorem Ipsum')}</TableCell>
                      <TableCell align="left">{t('Lorem Ipsum')}</TableCell>
                      <TableCell className={ classes.tableItem } align="left">
                        <LaunchIcon style={{ paddingRight: '5.5px' }} fontSize="small"/>{t('Lorem Ipsum')}
                      </TableCell>
                    </TableRow>
                </TableBody>
              </Table>
            </TableContainer>
        </Paper>
      </div>
    );
  }
}

RiskAnalysisCharacterizationComponent.propTypes = {
  risk: PropTypes.object,
  classes: PropTypes.object,
  t: PropTypes.func,
  fldt: PropTypes.func,
};

const RiskAnalysisCharacterization = createFragmentContainer(
  RiskAnalysisCharacterizationComponent,
  {
    risk: graphql`
      fragment RiskAnalysisCharacterization_risk on ComputingDeviceAsset {
        id
        asset_id
        asset_type
        asset_tag
        description
        version
        vendor_name
        serial_number
        release_date
        # responsible_parties
        operational_status
        labels
      }
    `,
  },
);

export default compose(inject18n, withStyles(styles))(RiskAnalysisCharacterization);
