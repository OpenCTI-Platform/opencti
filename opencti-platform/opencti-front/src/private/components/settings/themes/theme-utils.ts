export const getLoginAsideType = (values: {
  theme_login_aside_color?: string | null;
  theme_login_aside_gradient_start?: string | null;
  theme_login_aside_gradient_end?: string | null;
  theme_login_aside_image?: string | null;
}) => {
  if (values.theme_login_aside_image) return 'image';
  if (values.theme_login_aside_gradient_start || values.theme_login_aside_gradient_end) return 'gradient';
  if (values.theme_login_aside_color) return 'color';
  return '';
};
