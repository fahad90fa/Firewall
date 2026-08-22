import { useEffect, useState } from "react";
import Nav from "./components/Nav";
import Hero from "./components/Hero";
import ThreatFeed from "./components/ThreatFeed";
import Features from "./components/Features";
import HowItWorks from "./components/HowItWorks";
import Platforms from "./components/Platforms";
import Pricing from "./components/Pricing";
import Footer from "./components/Footer";
import DownloadPage from "./components/DownloadPage";

type Route = "home" | "download";

function readRoute(): Route {
  return window.location.hash.replace(/^#\/?/, "") === "download" ? "download" : "home";
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
      {route === "download" ? (
        <main>
          <DownloadPage />
        </main>
      ) : (
        <main>
          <Hero />
          <ThreatFeed />
          <Features />
          <HowItWorks />
          <Platforms />
          <Pricing />
        </main>
      )}
      <Footer />
    </div>
  );
}
