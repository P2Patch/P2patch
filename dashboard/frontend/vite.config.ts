import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";

// `vite build --mode static` (npm run build:static) compiles the *published*
// build: __PUBLISHED__ becomes the literal `true`, which flips the app to fetch
// the frozen static API tree (dashboard/export_static.py) and drops every
// control surface. A normal build (served by FastAPI locally) keeps it `false`.
//
// The /api proxy targets the FastAPI backend during `npm run dev`. To preview a
// published build locally, serve the built dist/ with any static server (e.g.
// `python3 -m http.server` — see dashboard/publish.sh --build), which mirrors
// the static host; `vite preview` would forward /api to the (absent) backend.
export default defineConfig(({ mode }) => ({
  plugins: [react()],
  define: {
    __PUBLISHED__: JSON.stringify(mode === "static"),
  },
  server: {
    port: 5173,
    proxy: {
      "/api": "http://localhost:8000",
    },
  },
}));
