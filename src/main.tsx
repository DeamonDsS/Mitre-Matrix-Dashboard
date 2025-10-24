import './index.css' // <--- บรรทัดนี้สำคัญที่สุด! ต้องมีอยู่
import { RouterProvider, createBrowserRouter } from "react-router-dom";
import ReactDOM from "react-dom/client";
import App from "./App.tsx";
import React from "react";
import Dashboard from "./pages/dashboard/index.tsx";
import MitreAttackNavigator from './pages/mitre-framework/index.tsx';


const router = createBrowserRouter([
  {
    path: "/",
    element: <App />, // Root layout or main application component
    children: [
      { index: true, element: <Dashboard /> },
      { path: "/mitre-navigator", element: <MitreAttackNavigator /> },
    ],
      
  },
]);

ReactDOM.createRoot(document.getElementById("root")!).render(
  <React.StrictMode>
    <RouterProvider router={router} />
  </React.StrictMode>
);
