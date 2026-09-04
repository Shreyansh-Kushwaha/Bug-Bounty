import { Outlet } from "react-router-dom";
import Navbar from "./Navbar";
import Footer from "./Footer";
import Login from "../pages/Login";
import { AuthProvider, useAuth } from "../hooks/useAuth";

function Gate() {
  const { ready, authEnabled, authed } = useAuth();

  if (!ready) {
    return (
      <div className="min-h-screen grid place-items-center text-fg-dim">Loading…</div>
    );
  }
  if (authEnabled && !authed) {
    return <Login />;
  }
  return (
    <div className="min-h-screen flex flex-col">
      <Navbar />
      <main className="flex-1 w-full max-w-site mx-auto px-6 py-8">
        <Outlet />
      </main>
      <Footer />
    </div>
  );
}

export default function Layout() {
  return (
    <AuthProvider>
      <Gate />
    </AuthProvider>
  );
}
