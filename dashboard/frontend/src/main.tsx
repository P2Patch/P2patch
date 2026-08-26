import React from "react";
import ReactDOM from "react-dom/client";
import { createBrowserRouter, Navigate, RouterProvider } from "react-router-dom";
import { App } from "./App";
import { PUBLISHED } from "./api";
import { Overview } from "./pages/Overview";
import { RunDetail } from "./pages/RunDetail";
import { Live } from "./pages/Live";
import { Compare } from "./pages/Compare";
import { OtherProjects } from "./pages/OtherProjects";
import { San2Patch } from "./pages/San2Patch";
import { San2PatchDetail } from "./pages/San2PatchDetail";
import { PatchAgent } from "./pages/PatchAgent";
import { PatchAgentDetail } from "./pages/PatchAgentDetail";
import { LoopRepairDetail } from "./pages/LoopRepairDetail";
import { ResidualTriage } from "./pages/ResidualTriage";
import "./index.css";

const router = createBrowserRouter([
  {
    path: "/",
    element: <App />,
    children: [
      { index: true, element: <Overview /> },
      { path: "runs/:id", element: <RunDetail /> },
      { path: "compare", element: <Compare /> },
      { path: "other-projects", element: <OtherProjects /> },
      { path: "other-projects/:key", element: <LoopRepairDetail /> },
      // San2Patch lives on its own route, not under other-projects/: that page and
      // its LoopRepair data are owned and analysed separately.
      { path: "residual-audit", element: <ResidualTriage /> },
      { path: "san2patch", element: <San2Patch /> },
      { path: "san2patch/:key", element: <San2PatchDetail /> },
      // PatchAgent gets its own route for the same reason San2Patch does: a
      // separately owned baseline with its own caveats, not a row in someone
      // else's table.
      { path: "patchagent", element: <PatchAgent /> },
      { path: "patchagent/:key", element: <PatchAgentDetail /> },
      // The live monitor spawns real pipeline runs — omit it from the published
      // snapshot and send any stale /live link back to the experiments list.
      { path: "live", element: PUBLISHED ? <Navigate to="/" replace /> : <Live /> },
      { path: "*", element: <Navigate to="/" replace /> },
    ],
  },
]);

ReactDOM.createRoot(document.getElementById("root")!).render(
  <React.StrictMode>
    <RouterProvider router={router} />
  </React.StrictMode>,
);
