import React from 'react'
import ReactDOM from 'react-dom/client'
import { BrowserRouter, Routes, Route, Navigate } from 'react-router-dom'
import './index.css'
 
import Login       from './pages/Login.jsx'
import Layout      from './components/Layout.jsx'
import Overview    from './pages/Overview.jsx'
import Devices     from './pages/Devices.jsx'
import PortScan    from './pages/PortScan.jsx'
import PwnedCheck  from './pages/PwnedCheck.jsx'
import AIAdvisor   from './pages/AIAdvisor.jsx'
import AgentSetup from './pages/AgentSetup.jsx'
import { auth_state } from './services/api.js'
 
/**
 * PrivateRoute — no longer reads localStorage.
 *
 * The JWT is in an httpOnly cookie; we can't inspect it from JS.
 * We use sessionStorage for the username as a lightweight "are we logged in?"
 * signal. If the cookie is actually expired, the first API call will 401
 * and the app/layout will redirect to /login.
 */
function PrivateRoute({ children }) {
  return auth_state.isLoggedIn() ? children : <Navigate to="/login" replace />
}
 
ReactDOM.createRoot(document.getElementById('root')).render(
  <React.StrictMode>
    <BrowserRouter>
      <Routes>
        <Route path="/login" element={<Login />} />
        <Route path="/" element={<PrivateRoute><Layout /></PrivateRoute>}>
          <Route index element={<Navigate to="/overview" replace />} />
          <Route path="overview"  element={<Overview />} />
          <Route path="devices"   element={<Devices />} />
          <Route path="ports"     element={<PortScan />} />
          <Route path="password"  element={<PwnedCheck />} />
          <Route path="ai"        element={<AIAdvisor />} />
          <Route path="/agent-setup" element={<AgentSetup />} />
        </Route>
      </Routes>
    </BrowserRouter>
  </React.StrictMode>
)
