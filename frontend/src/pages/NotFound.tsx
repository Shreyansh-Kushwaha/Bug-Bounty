import { Link } from "react-router-dom";

export default function NotFound() {
  return (
    <section className="card text-center">
      <h1 className="text-2xl font-semibold mb-2 text-fg">404 — Not found</h1>
      <p className="text-fg-muted mb-4">That page doesn't exist (or it never did).</p>
      <Link to="/" className="btn">Go home</Link>
    </section>
  );
}
