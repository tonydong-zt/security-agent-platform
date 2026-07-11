import { Activity, BookOpen, FileSearch, FileText, ListChecks, ShieldCheck } from "lucide-react";
import { useState } from "react";
import { ActionApproval } from "./pages/ActionApproval";
import { CaseDetail } from "./pages/CaseDetail";
import { Dashboard } from "./pages/Dashboard";
import { Investigation } from "./pages/Investigation";
import { KnowledgeBase } from "./pages/KnowledgeBase";
import { LogUpload } from "./pages/LogUpload";

const tabs = [
  { key: "dashboard", label: "Dashboard", icon: Activity },
  { key: "kb", label: "Knowledge", icon: BookOpen },
  { key: "logs", label: "Logs", icon: FileText },
  { key: "investigate", label: "Investigate", icon: FileSearch },
  { key: "case", label: "Case", icon: ListChecks },
  { key: "actions", label: "Actions", icon: ShieldCheck }
];

export function App() {
  const [tab, setTab] = useState("dashboard");
  const page =
    tab === "kb" ? <KnowledgeBase /> :
    tab === "logs" ? <LogUpload /> :
    tab === "investigate" ? <Investigation /> :
    tab === "case" ? <CaseDetail /> :
    tab === "actions" ? <ActionApproval /> :
    <Dashboard />;

  return (
    <div className="app-shell">
      <aside>
        <div className="brand">AI Security Agent</div>
        <nav>
          {tabs.map((item) => {
            const Icon = item.icon;
            return (
              <button key={item.key} className={tab === item.key ? "active" : ""} onClick={() => setTab(item.key)}>
                <Icon size={18} />
                <span>{item.label}</span>
              </button>
            );
          })}
        </nav>
      </aside>
      <main>{page}</main>
    </div>
  );
}
