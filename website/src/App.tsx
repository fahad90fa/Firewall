import Nav from "./components/Nav";
import Hero from "./components/Hero";
import ThreatFeed from "./components/ThreatFeed";
import Features from "./components/Features";
import HowItWorks from "./components/HowItWorks";
import Platforms from "./components/Platforms";
import Pricing from "./components/Pricing";
import Footer from "./components/Footer";

export default function App() {
  return (
    <div className="min-h-screen">
      <Nav />
      <main>
        <Hero />
        <ThreatFeed />
        <Features />
        <HowItWorks />
        <Platforms />
        <Pricing />
        <Footer />
      </main>
    </div>
  );
}
