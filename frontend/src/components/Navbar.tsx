import { useState } from "react";
import { NavLink, Link } from "react-router-dom";
import { Menu, Shield, X } from "lucide-react";
import ThemeToggle from "./ThemeToggle";

const links = [
  { to: "/", label: "Home", end: true },
  { to: "/features", label: "Features" },
  { to: "/dashboard", label: "Dashboard" },
  { to: "/findings", label: "Findings" },
  { to: "/audit", label: "Audit" },
  { to: "/about", label: "About" },
  { to: "/contact", label: "Contact" },
];

export default function Navbar() {
  const [open, setOpen] = useState(false);

  return (
    <header className="sticky top-0 z-50 bg-bg-elev/90 backdrop-blur-md border-b border-border">
      <div className="max-w-site mx-auto px-6 py-3 flex items-center justify-between gap-4">
        <Link to="/" className="flex items-center gap-2 font-semibold text-fg">
          <span
            className="grid place-items-center w-7 h-7 rounded-md text-white shadow-soft"
            style={{ background: "linear-gradient(135deg, var(--accent), var(--accent-hover))" }}
            aria-hidden
          >
            <Shield size={16} strokeWidth={2.4} />
          </span>
          <span>Bug-Bounty</span>
        </Link>

        <nav className="hidden md:flex items-center gap-1">
          {links.map((l) => (
            <NavLink
              key={l.to}
              to={l.to}
              end={l.end}
              className={({ isActive }) => `nav-link ${isActive ? "active" : ""}`}
            >
              {l.label}
            </NavLink>
          ))}
        </nav>

        <div className="flex items-center gap-2">
          <ThemeToggle />
          <button
            onClick={() => setOpen((o) => !o)}
            aria-label="Toggle menu"
            aria-expanded={open}
            className="md:hidden grid place-items-center w-9 h-9 rounded-lg border border-border text-fg-muted
                       hover:bg-bg-soft hover:text-fg"
          >
            {open ? <X size={18} /> : <Menu size={18} />}
          </button>
        </div>
      </div>

      {open && (
        <nav
          className="md:hidden bg-bg-elev border-t border-border px-4 py-2 flex flex-col gap-1"
          onClick={() => setOpen(false)}
        >
          {links.map((l) => (
            <NavLink
              key={l.to}
              to={l.to}
              end={l.end}
              className={({ isActive }) => `nav-link ${isActive ? "active" : ""}`}
            >
              {l.label}
            </NavLink>
          ))}
        </nav>
      )}
    </header>
  );
}
