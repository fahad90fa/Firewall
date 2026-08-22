import { useEffect, useRef, useState } from "react";
import Nav from "./components/Nav";
import Hero from "./components/Hero";
import ThreatFeed from "./components/ThreatFeed";
import Features from "./components/Features";
import HowItWorks from "./components/HowItWorks";
import Platforms from "./components/Platforms";
import Pricing from "./components/Pricing";
import Footer from "./components/Footer";
import DownloadPage from "./components/DownloadPage";
import AdminPage from "./components/AdminPage";

type Route = "home" | "download" | "admin";

const ROUTE_LABEL: Record<Route, string> = {
  home: "Home",
  download: "Download",
  admin: "Admin console",
};

function readRoute(): Route {
  const h = window.location.hash.replace(/^#\/?/, "");
  if (h === "download") return "download";
  if (h === "admin") return "admin";
  return "home";
}

function useHashRoute(): Route {
  const [route, setRoute] = useState<Route>(readRoute);
  useEffect(() => {
    const onChange = () => setRoute(readRoute());
    window.addEventListener("hashchange", onChange);
    return () => window.removeEventListener("hashchange", onChange);
  }, []);
  return route;
}

export default function App() {
  const route = useHashRoute();
  const mainRef = useRef<HTMLElement | null>(null);
  const firstRender = useRef(true);
  const [announce, setAnnounce] = useState("");

  // On a client-side route change there is no browser page-load, so focus and
  // the screen-reader's reading position would otherwise stay put. Move focus
  // to the top of <main> and announce the new page. Skip the very first render
  // so we don't yank focus on initial load.
  useEffect(() => {
    if (firstRender.current) {
      firstRender.current = false;
      return;
    }
    setAnnounce(`${ROUTE_LABEL[route]} page`);
    const el = mainRef.current;
    if (el) requestAnimationFrame(() => el.focus());
  }, [route]);

  // Returning to the landing page with a section hash (e.g. #pricing) should
  // scroll there, even though the section only just mounted.
  useEffect(() => {
    if (route !== "home") return;
    const id = window.location.hash.replace(/^#/, "");
    if (!id || id === "download") return;
    const el = document.getElementById(id);
    if (el) requestAnimationFrame(() => el.scrollIntoView({ behavior: "smooth" }));
  }, [route]);

  return (
    <div className="min-h-screen">
      <Nav />
      {/* aria-live region: announces client-side page changes to assistive tech */}
      <div aria-live="polite" className="sr-only">
        {announce}
      </div>
      <main ref={mainRef} tabIndex={-1} className="outline-none">
        {route === "download" ? (
          <DownloadPage />
        ) : route === "admin" ? (
          <AdminPage />
        ) : (
          <>
            <Hero />
            <ThreatFeed />
            <Features />
            <HowItWorks />
            <Platforms />
            <Pricing />
          </>
        )}
      </main>
      <Footer />
    </div>
  );
}
