/**
 * Three blurred gradient orbs that drift behind the hero.
 * Pure CSS animation — cheap, no JS rAF loops.
 */
export default function AnimatedBg() {
  return (
    <div className="orbs" aria-hidden="true">
      <span
        className="orb animate-float"
        style={{
          width: 480, height: 480,
          top: -140, left: -120,
          background: "var(--accent)",
        }}
      />
      <span
        className="orb animate-float-slow"
        style={{
          width: 380, height: 380,
          top: 80, right: -120,
          background: "var(--accent-hover)",
          animationDelay: "-7s",
        }}
      />
      <span
        className="orb animate-float-slower"
        style={{
          width: 340, height: 340,
          bottom: -180, left: "32%",
          background: "#ec4899", // a touch of pink for visual contrast
          animationDelay: "-14s",
          opacity: 0.35,
        }}
      />
    </div>
  );
}
