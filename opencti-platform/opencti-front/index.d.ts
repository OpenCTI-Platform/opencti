declare module "*.png";
declare module "*.jpg";
declare module "*.svg";
declare module "react-rectangle-selection";

// Global window properties injected at runtime
interface Window {
  BASE_PATH: string;
  BACK_END_URL: string;
}
