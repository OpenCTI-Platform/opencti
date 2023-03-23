import React, { FunctionComponent } from 'react';
import ListItemIcon from '@mui/material/ListItemIcon';
import ListItemText from '@mui/material/ListItemText';
import { CasesOutlined, KeyboardArrowRightOutlined } from '@mui/icons-material';
import makeStyles from '@mui/styles/makeStyles';
import { graphql, useFragment } from 'react-relay';
import { Link } from 'react-router-dom';
import ListItem from '@mui/material/ListItem';
import Checkbox from '@mui/material/Checkbox';
import { Theme } from '../../../../components/Theme';
import { CaseTemplateLine_node$key, CaseTemplateLine_node$data } from './__generated__/CaseTemplateLine_node.graphql';
import { DataColumns } from '../../../../components/list_lines';

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
    paddingRight: 5,
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
      pageInfo {
        globalCount
      }
    }
  }
`;

interface CaseTemplateLineProps {
  node: CaseTemplateLine_node$key;
  dataColumns: DataColumns;
  selectedElements: Record<string, CaseTemplateLine_node$data>;
  deSelectedElements: Record<string, CaseTemplateLine_node$data>;
  onToggleEntity: (
    entity: CaseTemplateLine_node$data,
    event: React.SyntheticEvent
  ) => void;
  selectAll: boolean;
  onToggleShiftEntity: (
    index: number,
    entity: CaseTemplateLine_node$data,
    event: React.SyntheticEvent
  ) => void;
  index: number;
}

const CaseTemplateLine: FunctionComponent<CaseTemplateLineProps> = ({
  node,
  dataColumns,
  selectedElements,
  deSelectedElements,
  onToggleEntity,
  selectAll,
  onToggleShiftEntity,
  index,
}) => {
  const classes = useStyles();

  const data = useFragment(CaseTemplateLineFragment, node);

  return (
    <ListItem
      classes={{ root: classes.item }}
      component={Link}
      divider
      button
      to={`/dashboard/settings/vocabularies/caseTemplates/${data.id}`}
    >
      <ListItemIcon
        classes={{ root: classes.itemIcon }}
        style={{ minWidth: 40 }}
        onClick={(event) => (event.shiftKey
          ? onToggleShiftEntity(index, data, event)
          : onToggleEntity(data, event))
        }
      >
        <Checkbox
          edge="start"
          checked={
            (selectAll && !(data.id in (deSelectedElements || {})))
            || data.id in (selectedElements || {})
          }
          disableRipple={true}
        />
      </ListItemIcon>
      <ListItemIcon>
        <CasesOutlined />
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
