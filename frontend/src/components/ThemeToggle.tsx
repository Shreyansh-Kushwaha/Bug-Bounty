import { useState } from "react";
import { Moon, Sun } from "lucide-react";
import { useTheme } from "../hooks/useTheme";

/**
 * Springy sun ↔ moon morph with a one-shot ring pulse on click.
 * The icons are absolutely-positioned siblings; CSS toggles which is
 * visible based on the [data-theme] attribute, with a cubic-bezier bounce.
 */
export default function ThemeToggle() {
  const { theme, toggle } = useTheme();
  const [ringing, setRinging] = useState(false);

  function onClick() {
    toggle();
    setRinging(true);
    window.setTimeout(() => setRinging(false), 600);
  }

  return (
    <button
      onClick={onClick}
      className={`theme-toggle ${ringing ? "ringing" : ""}`}
      aria-label="Toggle theme"
      title={theme === "dark" ? "Switch to light" : "Switch to dark"}
    >
      <span className="ti ti-sun"><Sun size={18} /></span>
      <span className="ti ti-moon"><Moon size={18} /></span>
    </button>
  );
}
