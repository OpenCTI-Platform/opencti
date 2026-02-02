import { capitalizeFirstLetter, EMPTY_VALUE } from 'src/utils/String';

interface TextListProps {
  list?: readonly (string | null | undefined)[] | null | undefined;
}

const TextList = ({ list }: TextListProps) => {
  return (
    <>
      {list && list?.length > 0
        ? (list.map((element) => element && capitalizeFirstLetter(element)).join(', '))
        : EMPTY_VALUE}
    </>
  );
};

export default TextList;
