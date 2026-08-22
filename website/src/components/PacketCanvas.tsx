import { useEffect, useRef } from "react";

type Packet = {
  x: number;
  y: number;
  lane: number;
  speed: number;
  hostile: boolean;
  state: "flying" | "burst";
  life: number;
};

/**
 * The hero's ambient scene: a stream of packets crossing toward a vertical
 * firewall wall. Hostile packets (most of them) burst red at the wall; a few
 * legitimate ones pass a lit gate and continue. Canvas, not SVG, so hundreds of
 * particles stay cheap. Pauses under prefers-reduced-motion.
 */
export default function PacketCanvas() {
  const ref = useRef<HTMLCanvasElement | null>(null);

  useEffect(() => {
    const canvas = ref.current;
    if (!canvas) return;
    const ctx = canvas.getContext("2d");
    if (!ctx) return;

    const reduced = window.matchMedia("(prefers-reduced-motion: reduce)").matches;
    let raf = 0;
    let w = 0;
    let h = 0;
    let dpr = Math.min(window.devicePixelRatio || 1, 2);
    const packets: Packet[] = [];

    const wallX = () => w * 0.62;
    const gateTop = () => h * 0.42;
    const gateBottom = () => h * 0.58;

    function resize() {
      if (!canvas) return;
      const rect = canvas.getBoundingClientRect();
      w = rect.width;
      h = rect.height;
      dpr = Math.min(window.devicePixelRatio || 1, 2);
      canvas.width = Math.floor(w * dpr);
      canvas.height = Math.floor(h * dpr);
      ctx!.setTransform(dpr, 0, 0, dpr, 0, 0);
    }

    function spawn() {
      const lane = Math.random();
      const y = 20 + lane * (h - 40);
      const inGate = y > gateTop() + 6 && y < gateBottom() - 6;
      const hostile = inGate ? Math.random() > 0.55 : true;
      packets.push({
        x: -20,
        y,
        lane,
        speed: 1.1 + Math.random() * 1.9,
        hostile,
        state: "flying",
        life: 0,
      });
    }

    function draw() {
      if (!ctx) return;
      ctx.clearRect(0, 0, w, h);

      // Wall
      const wx = wallX();
      const gt = gateTop();
      const gb = gateBottom();
      ctx.save();
      ctx.fillStyle = "rgba(30,58,95,0.9)";
      ctx.strokeStyle = "rgba(56,189,248,0.28)";
      ctx.lineWidth = 1;
      roundRect(ctx, wx, 8, 10, gt - 16, 3);
      ctx.fill();
      roundRect(ctx, wx, gb + 8, 10, h - gb - 16, 3);
      ctx.fill();
      // gate
      ctx.fillStyle = "rgba(11,59,46,0.85)";
      ctx.strokeStyle = "rgba(52,211,153,0.55)";
      roundRect(ctx, wx - 1, gt + 4, 12, gb - gt - 8, 3);
      ctx.fill();
      ctx.stroke();
      ctx.restore();

      for (let i = packets.length - 1; i >= 0; i--) {
        const p = packets[i];
        if (p.state === "flying") {
          p.x += p.speed;
          const atWall = p.x >= wx - 6;
          const inGate = p.y > gt + 6 && p.y < gb - 6;
          if (atWall && p.hostile && !inGate) {
            p.state = "burst";
            p.life = 0;
          } else if (p.x > w + 30) {
            packets.splice(i, 1);
            continue;
          }
          const color = p.hostile ? "251,113,133" : "52,211,153";
          ctx.fillStyle = `rgba(${color},0.95)`;
          ctx.shadowColor = `rgba(${color},0.9)`;
          ctx.shadowBlur = 8;
          roundRect(ctx, p.x, p.y - 5, 16, 10, 2.5);
          ctx.fill();
          ctx.shadowBlur = 0;
          // trail
          ctx.fillStyle = `rgba(${color},0.12)`;
          roundRect(ctx, p.x - 22, p.y - 3, 22, 6, 2);
          ctx.fill();
        } else {
          // burst
          p.life += 1;
          const r = p.life * 1.4;
          const a = Math.max(0, 0.7 - p.life * 0.05);
          ctx.strokeStyle = `rgba(251,113,133,${a})`;
          ctx.lineWidth = 2;
          ctx.beginPath();
          ctx.arc(wx, p.y, r, 0, Math.PI * 2);
          ctx.stroke();
          if (p.life > 16) packets.splice(i, 1);
        }
      }
    }

    let acc = 0;
    let last = 0;
    function loop(t: number) {
      const dt = Math.min(48, t - last);
      last = t;
      acc += dt;
      // spawn cadence
      if (acc > 90 && packets.length < 90) {
        acc = 0;
        spawn();
        if (Math.random() > 0.5) spawn();
      }
      draw();
      raf = requestAnimationFrame(loop);
    }

    resize();
    window.addEventListener("resize", resize);
    if (reduced) {
      // one static frame with a few packets
      for (let i = 0; i < 10; i++) spawn();
      packets.forEach((p) => (p.x = Math.random() * wallX()));
      draw();
    } else {
      raf = requestAnimationFrame(loop);
    }

    return () => {
      cancelAnimationFrame(raf);
      window.removeEventListener("resize", resize);
    };
  }, []);

  return <canvas ref={ref} className="h-full w-full" aria-hidden="true" />;
}

function roundRect(ctx: CanvasRenderingContext2D, x: number, y: number, w: number, h: number, r: number) {
  const rr = Math.min(r, w / 2, h / 2);
  ctx.beginPath();
  ctx.moveTo(x + rr, y);
  ctx.arcTo(x + w, y, x + w, y + h, rr);
  ctx.arcTo(x + w, y + h, x, y + h, rr);
  ctx.arcTo(x, y + h, x, y, rr);
  ctx.arcTo(x, y, x + w, y, rr);
  ctx.closePath();
}
