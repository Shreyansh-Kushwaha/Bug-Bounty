import { Outlet } from "react-router-dom";
import Navbar from "./Navbar";
import Footer from "./Footer";

export default function Layout() {
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
