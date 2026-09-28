import { NavLink } from "react-router-dom";

import {
  LayoutDashboard,
  Folder,
  FileText,
  ScanSearch,
  FileBarChart
} from "lucide-react";


function Sidebar() {
  return (
    <aside className="sidebar">

      {/* =========================
          LOGO
      ========================== */}
      <div className="logo">
        <h2>ForensiRansom AI</h2>
        <p>Digital Forensic Platform</p>
      </div>


      {/* =========================
          NAVIGATION
      ========================== */}
      <nav>

        {/* Dashboard */}
        <NavLink to="/dashboard">
          <LayoutDashboard size={20} />
          <span>Dashboard</span>
        </NavLink>


        {/* Cases */}
        <NavLink to="/cases">
          <Folder size={20} />
          <span>Cases</span>
        </NavLink>


        {/* Evidence */}
        <NavLink to="/evidence">
          <FileText size={20} />
          <span>Evidence</span>
        </NavLink>


        {/* Memory Analysis */}
        <NavLink to="/analysis">
          <ScanSearch size={20} />
          <span>Memory Analysis</span>
        </NavLink>


        {/* Reports */}
        <NavLink to="/report">
          <FileBarChart size={20} />
          <span>Reports</span>
        </NavLink>

      </nav>


      {/* =========================
          SIDEBAR FOOTER
      ========================== */}
      <div className="sidebar-footer">
        <p>ForensiRansom AI v1.0</p>
      </div>

    </aside>
  );
}


export default Sidebar;