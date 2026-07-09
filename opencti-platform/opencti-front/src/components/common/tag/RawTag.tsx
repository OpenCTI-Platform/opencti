import Tag, { TagProps } from './Tag';

type RawTagProps = Omit<TagProps, 'labelTextTransform'>;

export const RawTag = (props: RawTagProps) => <Tag {...props} labelTextTransform="none" />;

export default RawTag;
