import { MouseEvent } from 'react';
import { Star, StarBorder } from '@mui/icons-material';
import { graphql } from 'react-relay';
import useApiMutation from '../../../utils/hooks/useApiMutation';
import { deleteNode, insertNode } from '../../../utils/store';
import IconButton from '../button/IconButton';

const bookmarkAddMutation = graphql`
  mutation BookmarkToggleAddMutation($id: ID!, $type: String!) {
    bookmarkAdd(id: $id, type: $type) {
      id
      ...StixDomainObjectBookmark_node
    }
  }
`;

const bookmarkDeleteMutation = graphql`
  mutation BookmarkToggleDeleteMutation($id: ID!) {
    bookmarkDelete(id: $id)
  }
`;

interface BookmarkToggleProps {
  stixId: string;
  stixEntityType: string;
  isBookmarked: boolean;
}

const BookmarkToggle = ({
  stixId,
  stixEntityType,
  isBookmarked,
}: BookmarkToggleProps) => {
  const [addMutation] = useApiMutation(bookmarkAddMutation);
  const [deleteMutation] = useApiMutation(bookmarkDeleteMutation);

  const addBookmark = () => {
    addMutation({
      variables: { id: stixId, type: stixEntityType },
      updater: (store) => insertNode(
        store,
        'Pagination_bookmarks',
        { types: [stixEntityType] },
        'bookmarkAdd',
      ),
    });
  };

  const deleteBookMark = () => {
    deleteMutation({
      variables: { id: stixId },
      updater: (store) => {
        deleteNode(
          store,
          'Pagination_bookmarks',
          { types: [stixEntityType] },
          stixId,
        );
      },
    });
  };

  const toggle = (e: MouseEvent) => {
    e.stopPropagation();
    e.preventDefault();
    if (isBookmarked) deleteBookMark();
    else addBookmark();
  };

  return (
    <IconButton size="small" onClick={toggle}>
      {!isBookmarked ? <StarBorder /> : <Star />}
    </IconButton>
  );
};

export default BookmarkToggle;
