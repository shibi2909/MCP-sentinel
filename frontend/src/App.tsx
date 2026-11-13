import { useEffect, useState } from "react";
import { api, getToken, setToken, setUnauthorizedHandler, User } from "./api";
import Login from "./pages/Login";
import Overview from "./pages/Overview";
import Demos from "./pages/Demos";
import Playground from "./pages/Playground";
import Approvals from "./pages/Approvals";
import Integrity from "./pages/Integrity";
import Audit from "./pages/Audit";
import Controller from "./pages/Controller";
import Sandbox from "./pages/Sandbox";
import Experiments from "./pages/Experiments";

const PAGES = [
  { key: "overview", label: "Overview", icon: "▦", component: Overview },
  { key: "demos", label: "Demo Scenarios", icon: "▶", component: Demos },
  { key: "gateway", label: "Gateway & Requests", icon: "⇄", component: Playground },
  { key: "approvals", label: "Approval Queue", icon: "⏸", component: Approvals },
  { key: "integrity", label: "Tool Integrity", icon: "#", component: Integrity },
  { key: "audit", label: "Audit Log", icon: "⛓", component: Audit },
  { key: "controller", label: "Controller", icon: "∿", component: Controller },
  { key: "sandbox", label: "Sandbox", icon: "▢", component: Sandbox },
  { key: "experiments", label: "Experiments", icon: "≋", component: Experiments },
] as const;

type PageKey = (typeof PAGES)[number]["key"];

function currentPage(): PageKey {
  const hash = window.location.hash.replace("#", "");
  return (PAGES.find((p) => p.key === hash)?.key ?? "overview") as PageKey;
}

export default function App() {
  const [user, setUser] = useState<User | null>(null);
  const [checking, setChecking] = useState(!!getToken());
  const [page, setPage] = useState<PageKey>(currentPage());
  const [navOpen, setNavOpen] = useState(false);

  useEffect(() => {
    setUnauthorizedHandler(() => setUser(null));
    const onHash = () => setPage(currentPage());
    window.addEventListener("hashchange", onHash);
    if (getToken()) {
      api<User>("/api/auth/me")
        .then(setUser)
        .catch(() => setToken(null))
        .finally(() => setChecking(false));
    }
    return () => window.removeEventListener("hashchange", onHash);
  }, []);

  if (checking) return <div className="grid h-screen place-items-center text-ink-muted">Loading…</div>;
  if (!user) return <Login onLogin={setUser} />;

  const Active = PAGES.find((p) => p.key === page)!.component;
  const logout = () => {
    setToken(null);
    setUser(null);
  };

  return (
    <div className="flex min-h-screen">
      <aside
        className={`fixed inset-y-0 left-0 z-30 w-64 transform border-r border-white/5 bg-surface-1 transition md:static md:translate-x-0 ${
          navOpen ? "translate-x-0" : "-translate-x-full"
        }`}
      >
        <div className="flex items-center gap-2.5 px-5 py-5">
          <img src="/shield.svg" alt="" className="h-7 w-7" />
          <div>
            <div className="text-sm font-semibold">MCP-Sentinel</div>
            <div className="text-[11px] text-ink-muted">Control-theoretic MCP gateway</div>
          </div>
        </div>
        <nav className="space-y-0.5 px-3">
          {PAGES.map((p) => (
            <a
              key={p.key}
              href={`#${p.key}`}
              onClick={() => setNavOpen(false)}
              className={`flex items-center gap-3 rounded-lg px-3 py-2 text-sm transition ${
                page === p.key ? "bg-accent/15 text-ink-primary" : "text-ink-secondary hover:bg-surface-2"
              }`}
            >
              <span className="w-4 text-center text-ink-muted" aria-hidden>{p.icon}</span>
              {p.label}
            </a>
          ))}
        </nav>
        <div className="absolute inset-x-0 bottom-0 border-t border-white/5 p-4">
          <div className="text-sm font-medium">{user.username}</div>
          <div className="mb-3 text-xs capitalize text-ink-muted">Role: {user.role}</div>
          <button className="btn-secondary w-full" onClick={logout}>Sign out</button>
        </div>
      </aside>
      {navOpen && <div className="fixed inset-0 z-20 bg-black/50 md:hidden" onClick={() => setNavOpen(false)} />}
      <main className="min-w-0 flex-1">
        <header className="sticky top-0 z-10 flex items-center gap-3 border-b border-white/5 bg-surface-0/90 px-4 py-3 backdrop-blur md:px-8">
          <button className="btn-secondary md:hidden" onClick={() => setNavOpen(true)} aria-label="Open navigation">☰</button>
          <h1 className="text-lg font-semibold">{PAGES.find((p) => p.key === page)!.label}</h1>
        </header>
        <div className="px-4 py-6 md:px-8">
          <Active user={user} />
        </div>
      </main>
    </div>
  );
}
