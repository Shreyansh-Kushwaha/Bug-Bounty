import { Route, Routes } from "react-router-dom";
import Layout from "./components/Layout";
import Home from "./pages/Home";
import Features from "./pages/Features";
import Dashboard from "./pages/Dashboard";
import Findings from "./pages/Findings";
import Audit from "./pages/Audit";
import About from "./pages/About";
import Contact from "./pages/Contact";
import RunDetail from "./pages/RunDetail";
import Artifact from "./pages/Artifact";
import NotFound from "./pages/NotFound";

export default function App() {
  return (
    <Routes>
      <Route element={<Layout />}>
        <Route index element={<Home />} />
        <Route path="features" element={<Features />} />
        <Route path="dashboard" element={<Dashboard />} />
        <Route path="findings" element={<Findings />} />
        <Route path="audit" element={<Audit />} />
        <Route path="about" element={<About />} />
        <Route path="contact" element={<Contact />} />
        <Route path="runs/:runId" element={<RunDetail />} />
        <Route path="runs/:runId/artifact/:name" element={<Artifact />} />
        <Route path="*" element={<NotFound />} />
      </Route>
    </Routes>
  );
}
