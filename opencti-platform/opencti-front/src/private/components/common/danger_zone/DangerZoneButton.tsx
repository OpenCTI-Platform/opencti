import { CSSProperties } from 'react';
import DangerZoneBlock from './DangerZoneBlock';
import Button, { CustomButtonProps } from '../../../../components/common/button/Button';
import { useTheme } from '@mui/styles';
import { Theme } from '../../../../components/Theme';
import { SensitiveConfigType } from '../../../../utils/hooks/useSensitiveModifications';

type DangerZoneButtonProps = CustomButtonProps & {
  sensitiveType?: SensitiveConfigType;
};

const DangerZoneButton = ({
  sensitiveType,
  ...props
}: DangerZoneButtonProps) => {
  const theme = useTheme<Theme>();

  const rootStyle: CSSProperties = {
    position: 'relative',
    border: 'none',
    padding: 0,
    paddingTop: 0,
    margin: 0,
  };

  const titleStyle: CSSProperties = {
    position: 'absolute',
    zIndex: 2,
    left: 4,
    top: 1,
    fontSize: 8,
  };

  return (
    <DangerZoneBlock
      type={sensitiveType}
      sx={{ root: rootStyle, title: titleStyle }}
    >
      {({ disabled }) => {
        const buttonStyle: CSSProperties = {
          borderColor: theme.palette.dangerZone.main,
          color: !disabled
            ? theme.palette.dangerZone.text?.primary
            : theme.palette.dangerZone.text?.disabled,
        };
        return (
          <Button
            size="small"
            intent="destructive"
            variant="secondary"
            disabled={disabled}
            style={buttonStyle}
            {...props}
          />
        );
      }}
    </DangerZoneBlock>
  );
};

export default DangerZoneButton;
