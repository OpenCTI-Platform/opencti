import React, { Component } from "react";
import * as PropTypes from "prop-types";
import {
  compose,
  map,
  sortWith,
  ascend,
  descend,
  prop,
  groupBy,
  pipe,
  values,
  head,
  merge,
  concat,
  assoc,
  find,
  propEq
} from "ramda";
import graphql from "babel-plugin-relay/macro";
import { createFragmentContainer } from "react-relay";
import { Link } from "react-router-dom";
import { withStyles } from "@material-ui/core/styles";
import List from "@material-ui/core/List";
import ListItem from "@material-ui/core/ListItem";
import ListItemIcon from "@material-ui/core/ListItemIcon";
import ListItemText from "@material-ui/core/ListItemText";
import ListItemSecondaryAction from "@material-ui/core/ListItemSecondaryAction";
import { ArrowDropDown, ArrowDropUp } from "@material-ui/icons";
import { Tag } from "mdi-material-ui";
import inject18n from "../../../components/i18n";
import ItemConfidenceLevel from "../../../components/ItemConfidenceLevel";
import { dateFormat } from "../../../utils/Time";
import { resolveLink } from "../../../utils/Entity";
import ReportHeader from "./ReportHeader";
import ReportAddObservable from "./ReportAddObservable";
import ReportRefPopover from "./ReportRefPopover";
import { QueryRenderer } from "../../../relay/environment";

const reportObservablesQuery = graphql`
  query ReportObservablesQuery($id: String!, $relationType: String) {
    report(id: $id) {
      ...ReportHeader_report
      ...ReportObservables_report @arguments(relationType: $relationType)
    }
  }
`;

const styles = theme => ({
  linesContainer: {
    marginTop: 10
  },
  itemHead: {
    paddingLeft: 10,
    textTransform: "uppercase",
    cursor: "pointer"
  },
  item: {
    paddingLeft: 10,
    transition: "background-color 0.1s ease",
    cursor: "pointer",
    "&:hover": {
      background: "rgba(0, 0, 0, 0.1)"
    }
  },
  bodyItem: {
    height: "100%",
    fontSize: 13
  },
  itemIcon: {
    color: theme.palette.primary.main
  },
  goIcon: {
    position: "absolute",
    right: 10,
    marginRight: 0
  },
  inputLabel: {
    float: "left"
  },
  sortIcon: {
    float: "left",
    margin: "-5px 0 0 15px"
  }
});

const inlineStylesHeaders = {
  iconSort: {
    position: "absolute",
    margin: "0 0 0 5px",
    padding: 0,
    top: "0px"
  },
  entity_type: {
    float: "left",
    width: "10%",
    fontSize: 12,
    fontWeight: "700"
  },
  observable_value: {
    float: "left",
    width: "20%",
    fontSize: 12,
    fontWeight: "700"
  },
  threat: {
    float: "left",
    width: "15%",
    fontSize: 12,
    fontWeight: "700"
  },
  role_played: {
    float: "left",
    width: "10%",
    fontSize: 12,
    fontWeight: "700"
  },
  first_seen: {
    float: "left",
    width: "15%",
    fontSize: 12,
    fontWeight: "700"
  },
  last_seen: {
    float: "left",
    width: "15%",
    fontSize: 12,
    fontWeight: "700"
  },
  weight: {
    float: "left",
    fontSize: 12,
    fontWeight: "700"
  }
};

const inlineStyles = {
  entity_type: {
    float: "left",
    width: "10%",
    height: 20,
    whiteSpace: "nowrap",
    overflow: "hidden",
    textOverflow: "ellipsis"
  },
  observable_value: {
    float: "left",
    width: "20%",
    height: 20,
    whiteSpace: "nowrap",
    overflow: "hidden",
    textOverflow: "ellipsis"
  },
  threat: {
    float: "left",
    width: "15%",
    height: 20,
    whiteSpace: "nowrap",
    overflow: "hidden",
    textOverflow: "ellipsis"
  },
  role_played: {
    float: "left",
    width: "10%",
    height: 20,
    whiteSpace: "nowrap",
    overflow: "hidden",
    textOverflow: "ellipsis"
  },
  first_seen: {
    float: "left",
    width: "15%",
    height: 20,
    whiteSpace: "nowrap",
    overflow: "hidden",
    textOverflow: "ellipsis"
  },
  last_seen: {
    float: "left",
    width: "15%",
    height: 20,
    whiteSpace: "nowrap",
    overflow: "hidden",
    textOverflow: "ellipsis"
  },
  weight: {
    float: "left",
    height: 20,
    whiteSpace: "nowrap",
    overflow: "hidden",
    textOverflow: "ellipsis"
  }
};

class ReportObservablesComponent extends Component {
  constructor(props) {
    super(props);
    this.state = { sortBy: "type", orderAsc: false };
  }

  reverseBy(field) {
    this.setState({ sortBy: field, orderAsc: !this.state.orderAsc });
  }

  SortHeader(field, label, isSortable) {
    const { t } = this.props;
    const sortComponent = this.state.orderAsc ? (
      <ArrowDropDown style={inlineStylesHeaders.iconSort} />
    ) : (
      <ArrowDropUp style={inlineStylesHeaders.iconSort} />
    );
    if (isSortable) {
      return (
        <div
          style={inlineStylesHeaders[field]}
          onClick={this.reverseBy.bind(this, field)}
        >
          <span>{t(label)}</span>
          {this.state.sortBy === field ? sortComponent : ""}
        </div>
      );
    }
    return (
      <div style={inlineStylesHeaders[field]}>
        <span>{t(label)}</span>
      </div>
    );
  }

  render() {
    const { t, fd, classes, report, reportId } = this.props;
    const observableRefs = map(
      n => ({ id: n.node.id, relationId: n.relation.id }),
      report.observableRefs.edges
    );
    const relationRefs = pipe(
      map(n => assoc("relation", n.relation, n.node)),
      groupBy(prop("id")),
      values,
      map(n => head(n)),
      map(n =>
        n.to.observable_value
          ? merge(n, {
              entity_type: n.to.entity_type,
              threat: n.from.name,
              threat_id: n.from.id,
              threat_type: n.from.entity_type,
              observable_id: n.to.id,
              observable_value: n.to.observable_value
            })
          : merge(n, {
              entity_type: n.from.entity_type,
              threat: n.to.name,
              threat_id: n.to.id,
              threat_type: n.to.entity_type,
              observable_id: n.from.id,
              observable_value: n.from.observable_value
            })
      ),
      map(n =>
        assoc(
          "observableRelationId",
          find(propEq("id", n.observable_id))(observableRefs).id,
          n
        )
      )
    )(report.relationRefs.edges);
    const observableRefsIds = map(n => n.id, observableRefs);
    const objectRefsIds = concat(
      observableRefsIds,
      map(n => n.node.id, report.objectRefs.edges)
    );
    const sort = sortWith(
      this.state.orderAsc
        ? [ascend(prop(this.state.sortBy))]
        : [descend(prop(this.state.sortBy))]
    );
    const sortedRelationRefs = sort(relationRefs);
    return (
      <div>
        <QueryRenderer
          query={reportObservablesQuery}
          variables={{ id: reportId, relationType: "indicates" }}
          render={({ props }) => {
            if (props && props.report) {
              return (
                <div>
                  <ReportHeader report={report} />
                  <List classes={{ root: classes.linesContainer }}>
                    <ListItem
                      classes={{ root: classes.itemHead }}
                      divider={false}
                      style={{ paddingTop: 0 }}
                    >
                      <ListItemIcon>
                        <span
                          style={{
                            padding: "0 8px 0 8px",
                            fontWeight: 700,
                            fontSize: 12
                          }}
                        >
                          #
                        </span>
                      </ListItemIcon>
                      <ListItemText
                        primary={
                          <div>
                            {this.SortHeader("entity_type", "Type", true)}
                            {this.SortHeader("observable_value", "Value", true)}
                            {this.SortHeader("threat", "Linked threat", true)}
                            {this.SortHeader("role_played", "Role", true)}
                            {this.SortHeader("first_seen", "First seen", true)}
                            {this.SortHeader("last_seen", "Last seen", true)}
                            {this.SortHeader(
                              "weight",
                              "Confidence level",
                              true
                            )}
                          </div>
                        }
                      />
                      <ListItemSecondaryAction>&nbsp;</ListItemSecondaryAction>
                    </ListItem>
                    {sortedRelationRefs.map(relationRef => {
                      const link = `${resolveLink(relationRef.threat_type)}/${
                        relationRef.threat_id
                      }/observables/relations`;
                      return (
                        <ListItem
                          key={relationRef.id}
                          classes={{ root: classes.item }}
                          divider={true}
                          component={Link}
                          to={`${link}/${relationRef.id}`}
                        >
                          <ListItemIcon classes={{ root: classes.itemIcon }}>
                            <Tag />
                          </ListItemIcon>
                          <ListItemText
                            primary={
                              <div>
                                <div
                                  className={classes.bodyItem}
                                  style={inlineStyles.entity_type}
                                >
                                  {t(`observable_${relationRef.entity_type}`)}
                                </div>
                                <div
                                  className={classes.bodyItem}
                                  style={inlineStyles.observable_value}
                                >
                                  {relationRef.observable_value}
                                </div>
                                <div
                                  className={classes.bodyItem}
                                  style={inlineStyles.threat}
                                >
                                  {relationRef.threat}
                                </div>
                                <div
                                  className={classes.bodyItem}
                                  style={inlineStyles.role_played}
                                >
                                  {relationRef.role_played
                                    ? t(relationRef.role_played)
                                    : t("Unknown")}
                                </div>
                                <div
                                  className={classes.bodyItem}
                                  style={inlineStyles.first_seen}
                                >
                                  {fd(relationRef.first_seen)}
                                </div>
                                <div
                                  className={classes.bodyItem}
                                  style={inlineStyles.last_seen}
                                >
                                  {fd(relationRef.last_seen)}
                                </div>
                                <div
                                  className={classes.bodyItem}
                                  style={inlineStyles.weight}
                                >
                                  <ItemConfidenceLevel
                                    level={
                                      relationRef.inferred
                                        ? 99
                                        : relationRef.weight
                                    }
                                    variant="inList"
                                  />
                                </div>
                              </div>
                            }
                          />
                          <ListItemSecondaryAction>
                            <ReportRefPopover
                              reportId={report.id}
                              entityId={relationRef.id}
                              relationId={relationRef.relation.id}
                              secondaryRelationId={
                                relationRef.observableRelationId
                              }
                              isRelation={true}
                            />
                          </ListItemSecondaryAction>
                        </ListItem>
                      );
                    })}
                  </List>
                </div>
              );
            }
            return <div> &nbsp; </div>;
          }}
        />
        <ReportAddObservable
          reportId={report.id}
          objectRefsIds={objectRefsIds}
          firstSeen={dateFormat(report.published)}
          lastSeen={dateFormat(report.published)}
          weight={report.source_confidence_level}
        />
      </div>
    );
  }
}

ReportObservablesComponent.propTypes = {
  reportId: PropTypes.string,
  report: PropTypes.object,
  classes: PropTypes.object,
  t: PropTypes.func,
  fd: PropTypes.func,
  history: PropTypes.object
};

const ReportObservables = createFragmentContainer(ReportObservablesComponent, {
  report: graphql`
    fragment ReportObservables_report on Report
      @argumentDefinitions(relationType: { type: "String" }) {
      id
      published
      source_confidence_level
      objectRefs {
        edges {
          node {
            id
          }
          relation {
            id
          }
        }
      }
      observableRefs {
        edges {
          node {
            id
          }
          relation {
            id
          }
        }
      }
      relationRefs(relationType: $relationType) {
        edges {
          node {
            id
            entity_type
            name
            relationship_type
            role_played
            first_seen
            last_seen
            weight
            created_at
            updated_at
            from {
              id
              entity_type
              name
              ... on StixObservable {
                observable_value
              }
            }
            to {
              id
              entity_type
              name
              ... on StixObservable {
                observable_value
              }
            }
          }
          relation {
            id
          }
        }
      }
      ...ReportHeader_report
    }
  `
});

export default compose(
  inject18n,
  withStyles(styles)
)(ReportObservables);
