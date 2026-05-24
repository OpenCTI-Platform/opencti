import { Box, Stack, Typography } from "@mui/material";
import { PropsWithChildren } from "react";
import SystemBanners from "../SystemBanners";
import { LoginRootPublicQuery$data } from "../../__generated__/LoginRootPublicQuery.graphql";
import LoginLogo from "./LoginLogo";
import SolarSystemAnimation from "./SolarSystemAnimation";
import { loginPanelSx } from "./loginStyles";

interface LoginLayoutProps extends PropsWithChildren {
  settings: LoginRootPublicQuery$data["publicSettings"];
}

const LoginLayout = ({ settings, children }: LoginLayoutProps) => {
  const currentYear = new Date().getFullYear();

  return (
    <>
      <SystemBanners settings={settings} />
      <Stack data-testid="login-page" direction="row" height="100%">
        <Box
          flex={3}
          sx={{
            position: "relative",
            display: "flex",
            flexDirection: "column",
            minWidth: 0,
            zIndex: 10,
            ...loginPanelSx,
          }}
        >
          <Box sx={{ p: 4, pb: 0 }}>
            <LoginLogo data={settings} />
          </Box>

          <Stack
            flex={1}
            justifyContent="center"
            alignItems="center"
            sx={{ px: 4, py: 6 }}
          >
            {children}
          </Stack>

          <Typography
            variant="body2"
            sx={{
              position: "absolute",
              bottom: 24,
              left: 32,
              color: "#9CA3AF",
              fontSize: 13,
            }}
          >
            {`© ResaaCTIP ${currentYear}`}
          </Typography>
        </Box>

        <Box
          flex={2}
          sx={{
            minWidth: 0,
            position: 'relative',
            background: 'linear-gradient(90.12deg, #533DE4 0.11%, #533DE4 99.9%)',
          }}
        >
          <SolarSystemAnimation />
        </Box>
      </Stack>
    </>
  );
};

export default LoginLayout;
