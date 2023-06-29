import React, { FunctionComponent } from 'react';
import ListItemIcon from '@mui/material/ListItemIcon';
import ListItemText from '@mui/material/ListItemText';
import { KeyboardArrowRightOutlined } from '@mui/icons-material';
import makeStyles from '@mui/styles/makeStyles';
import { graphql, useFragment } from 'react-relay';
import { Link } from 'react-router-dom';
import ListItem from '@mui/material/ListItem';
import { Theme } from '../../../../components/Theme';
import { CaseTemplateLine_node$key } from './__generated__/CaseTemplateLine_node.graphql';
import { DataColumns } from '../../../../components/list_lines';
import ItemIcon from '../../../../components/ItemIcon';

const useStyles = makeStyles<Theme>({
  item: {
    paddingLeft: 10,
    height: 50,
  },
  bodyItem: {
    height: 20,
    fontSize: 13,
    float: 'left',
    whiteSpace: 'nowrap',
    overflow: 'hidden',
    textOverflow: 'ellipsis',
    paddingRight: 10,
  },
  goIcon: {
    position: 'absolute',
    right: -10,
  },
});

export const CaseTemplateLineFragment = graphql`
  fragment CaseTemplateLine_node on CaseTemplate {
    entity_type
    id
    name
    description
    tasks {
      edges {
        node {
          id
          name
        }
      }
      pageInfo {
        globalCount
      }
    }
  }
`;

interface CaseTemplateLineProps {
  node: CaseTemplateLine_node$key;
  dataColumns: DataColumns;
}

const CaseTemplateLine: FunctionComponent<CaseTemplateLineProps> = ({
  node,
  dataColumns,
}) => {
  const classes = useStyles();

  const data = useFragment(CaseTemplateLineFragment, node);

  return (
    <ListItem
      classes={{ root: classes.item }}
      component={Link}
      divider
      button
      to={`/dashboard/settings/vocabularies/case_templates/${data.id}`}
    >
      <ListItemIcon>
        <ItemIcon type="Case-Template" />
      </ListItemIcon>
      <ListItemText
        primary={
          <>
            {Object.values(dataColumns).map((value) => (
              <div
                key={value.label}
                className={classes.bodyItem}
                style={{ width: value.width }}
              >
                {value.render?.(data)}
              </div>
            ))}
          </>
        }
      />
      <ListItemIcon classes={{ root: classes.goIcon }}>
        <KeyboardArrowRightOutlined />
      </ListItemIcon>
    </ListItem>
  );
};

export default CaseTemplateLine;
