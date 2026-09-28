import { BrowserRouter, Routes, Route } from "react-router-dom";

import Sidebar from "./components/Sidebar";

import Login from "./pages/Login";
import Register from "./pages/Register";
import Dashboard from "./pages/Dashboard";
import Cases from "./pages/Cases";
import Evidence from "./pages/Evidence";
import Analysis from "./pages/Analysis";
import Report from "./pages/Report";

function Layout({ children }) {
  return (
    <div className="app">
      <Sidebar />

      <main className="main-content">
        {children}
      </main>
    </div>
  );
}

function App() {
  return (
    <BrowserRouter>
      <Routes>

        {/* Authentication */}
        <Route path="/" element={<Login />} />
        <Route path="/register" element={<Register />} />

        {/* Main pages */}
        <Route
          path="/dashboard"
          element={
            <Layout>
              <Dashboard />
            </Layout>
          }
        />

        <Route
          path="/cases"
          element={
            <Layout>
              <Cases />
            </Layout>
          }
        />

        <Route
          path="/evidence"
          element={
            <Layout>
              <Evidence />
            </Layout>
          }
        />

        {/* Analysis */}
        <Route
          path="/analysis"
          element={
            <Layout>
              <Analysis />
            </Layout>
          }
        />

        <Route
          path="/analysis/:evidenceId"
          element={
            <Layout>
              <Analysis />
            </Layout>
          }
        />

        {/* Reports */}
        <Route
          path="/report"
          element={
            <Layout>
              <Report />
            </Layout>
          }
        />

        <Route
          path="/report/:evidenceId"
          element={
            <Layout>
              <Report />
            </Layout>
          }
        />

      </Routes>
    </BrowserRouter>
  );
}

export default App;