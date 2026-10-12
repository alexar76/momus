import { useMemo, useRef } from "react";
import { useFrame } from "@react-three/fiber";
import * as THREE from "three";

/* ===========================================================================
 *  MOMUS — THE UNBLINKING EYE (signature 3D scene)
 *
 *  Momus, god of blame, demanded that a WINDOW BE SET IN THE CHEST so any
 *  being's thoughts could be inspected. MOMUS the satellite is that window: an
 *  autonomous red team that probes the ecosystem's own components and signs
 *  what it finds. This scene is that myth made cinematic — an eye floating in
 *  the family's deep-space stage, actively scanning:
 *
 *    · a DARK PUPIL dome with a faint inner glow, breathing on a sum of
 *      incommensurate sines (so the dilation never looks like a loop), plus a
 *      sharp involuntary constriction whenever a finding lands;
 *    · an IRIS of 108 instanced radial blades over a procedural fbm-ish fibre
 *      shader, crimson at the limbus → amber at the pupil, counter-rotating
 *      against the pupil;
 *    · a SCAN SWEEP — a white-hot blade rotating through the iris on a slow
 *      period, with a decaying trail; the iris shader brightens everything the
 *      blade has just passed. This is MOMUS scanning;
 *    · the almond LENS OUTLINE, built mathematically (two circular lid arcs
 *      through (-W,0), (0,H), (W,0), bulged forward in z) and swept into a
 *      glowing tube, so the silhouette reads as an eye from the default camera;
 *    · a CHEST-WINDOW FRAME — four thin corner brackets floating in front of
 *      the eye, drifting;
 *    · PROBE BEAMS — streaks that fly from the pupil to six target orbs
 *      orbiting at a distance and return carrying a verdict. On arrival the orb
 *      flashes GREEN when the contract held (an honest negative) and CRIMSON
 *      when there is a finding. Roughly 1 in 12 is a finding — the truthful
 *      ratio for a healthy ecosystem, which is exactly what makes the rare red
 *      one land.
 *
 *  Everything is PROCEDURAL: three.js primitives, BufferGeometry built from
 *  maths, and inline GLSL. No model, texture, HDRI or font is loaded, and the
 *  scene makes no network requests.
 *
 *  Determinism: the probe/verdict sequence comes from an integer hash of the
 *  cycle index, so it is stable per frame — no per-frame Math.random(), no
 *  flicker. The per-frame hot path mutates preallocated buffers and scratch
 *  objects only (zero allocation), and the whole scene is ~22k triangles.
 * ========================================================================= */

// ---- palette (MOMUS crimson/amber over the family's cosmic backdrop) -----
const CRIMSON = new THREE.Color("#ff2d55");
const AMBER = new THREE.Color("#ff6b3d");
const ROSE = new THREE.Color("#ff8fb0");
const GREEN = new THREE.Color("#4ade80"); // the contract held
const IDLE = new THREE.Color("#6b5a78"); // un-probed target orb
const WHITE = new THREE.Color("#fff2f5");

// ---- eye geometry --------------------------------------------------------
const W = 3.55; // lens half-width
const H_UP = 1.62; // upper lid rise
const H_DN = 1.24; // lower lid drop (asymmetric — reads as an eye, not a lens)
const BULGE = 0.34; // forward bulge of the lid rim at the centre
const IRIS_IN = 0.34;
const IRIS_OUT = 1.3;
const IRIS_Z = 0.3;
const PUPIL_R = 0.5;

const N_IRIS = 108; // instanced iris blades
const N_ORBS = 6; // target orbs
const N_CH = 3; // concurrent probe channels

// probe cadence (seconds)
const P_PERIOD = 4.2;
const P_OUT = 1.6; // pupil → orb travel
const P_FLASH = 0.7; // orb verdict flash
const P_BACK_T0 = 1.9; // return leg start
const P_BACK_T1 = 3.7; // return leg end
const FINDING_MOD = 12; // ~1 in 12 probes is a finding

// what MOMUS actually probes (labels for the verdict ticker)
const TARGETS = [
  "aimarket-hub",
  "escrow bridge",
  "oracle federation",
  "factory pipeline",
  "metis verify",
  "school portal",
];

const TAU = Math.PI * 2;
const clamp = (v: number, lo: number, hi: number) => (v < lo ? lo : v > hi ? hi : v);
const smoothstep = (a: number, b: number, x: number) => {
  const t = clamp((x - a) / (b - a), 0, 1);
  return t * t * (3 - 2 * t);
};
/** 32-bit integer hash — the deterministic source for the probe sequence. */
function hash32(n: number): number {
  let x = n | 0;
  x = (x ^ 61) ^ (x >>> 16);
  x = (x + (x << 3)) | 0;
  x = x ^ (x >>> 4);
  x = Math.imul(x, 0x27d4eb2d);
  x = x ^ (x >>> 15);
  return x >>> 0;
}

// ---- the almond lid curve, built mathematically --------------------------
/** Circular arc through (-W,0), (0,h), (W,0): centre (0, h-R), R=(W²+h²)/2h. */
function lidY(x: number, h: number): number {
  const R = (W * W + h * h) / (2 * h);
  return Math.sqrt(Math.max(0, R * R - x * x)) + (h - R);
}
function lensLoop(scale: number, segs = 110): THREE.Vector3[] {
  const pts: THREE.Vector3[] = [];
  const push = (x: number, y: number) => {
    const zx = x / (W * scale);
    pts.push(new THREE.Vector3(x, y, BULGE * (1 - zx * zx)));
  };
  for (let i = 0; i <= segs; i++) {
    const x = (-W + (2 * W * i) / segs) * scale;
    push(x, lidY(x / scale, H_UP) * scale);
  }
  for (let i = segs - 1; i >= 1; i--) {
    const x = (-W + (2 * W * i) / segs) * scale;
    push(x, -lidY(x / scale, H_DN) * scale);
  }
  return pts;
}

// ---- iris shader (procedural fibre striations + the scan sweep) ----------
const IRIS_VERT = `
varying vec2 vP;
void main(){ vP = position.xy; gl_Position = projectionMatrix * modelViewMatrix * vec4(position,1.0); }
`;
const IRIS_FRAG = `
precision highp float;
varying vec2 vP;
uniform float uTime, uScan, uPupil, uTension;
float h1(float x){ return fract(sin(x*127.1)*43758.5453); }
void main(){
  float r = length(vP);
  float a = atan(vP.y, vP.x);

  // organic radial fibres: a coarse seeded band plus a fine ripple
  float seed  = h1(floor((a+3.14159265)*22.0));
  float fibre = 0.42 + 0.58*pow(0.5+0.5*sin(a*64.0 + seed*9.0 + r*5.0), 1.6);
  fibre *= 0.66 + 0.34*sin(a*171.0 + seed*20.0 - r*11.0);

  // radial envelope: soft inner/outer edges, hot pupil rim, bright limbal ring
  float inner  = smoothstep(uPupil-0.05, uPupil+0.22, r);
  float outer  = 1.0 - smoothstep(1.04, 1.30, r);
  float rim    = exp(-pow((r-(uPupil+0.09))/0.10, 2.0));
  float limbal = exp(-pow((r-1.225)/0.05, 2.0));

  // the scan sweep: tight leading edge + trail decaying behind it
  float d = mod(a - uScan + 3.14159265, 6.28318531) - 3.14159265;
  float lead  = exp(-pow(d/0.15, 2.0));
  float trail = exp(max(-7.0, d*2.6)) * step(d, 0.02);
  float scan  = lead*1.8 + trail*0.85;

  vec3 amber   = vec3(1.00, 0.42, 0.24);
  vec3 crimson = vec3(1.00, 0.18, 0.33);
  vec3 col = mix(amber, crimson, smoothstep(uPupil, 1.22, r));

  float br = (0.22 + 0.85*fibre) * inner * outer;
  br += rim*0.42*inner + limbal*0.34;
  br *= 1.0 + scan*1.25;
  col *= br;
  col += vec3(1.0, 0.76, 0.64) * lead * inner * outer * 0.55;
  col += vec3(1.0, 0.24, 0.34) * uTension * 0.22 * inner * outer;
  gl_FragColor = vec4(col * (0.97 + 0.03*sin(uTime*2.1 + r*6.0)), 1.0);
}
`;

export interface MomusSceneProps {
  /** Fires once per probe arrival so the page can run a verdict ticker. */
  onVerdict?: (text: string, kind: "held" | "finding") => void;
  /** Reduced-motion: everything runs ~8x slower and all flicker is dropped. */
  reduced?: boolean;
}

export default function Scene({ onVerdict, reduced = false }: MomusSceneProps) {
  const root = useRef<THREE.Group>(null);
  const eye = useRef<THREE.Group>(null);

  // pupil + inner glow + catchlight
  const pupilRef = useRef<THREE.Mesh>(null);
  const pupilMat = useRef<THREE.MeshStandardMaterial>(null);
  const glowRef = useRef<THREE.Mesh>(null);
  const glowMat = useRef<THREE.MeshBasicMaterial>(null);
  const catchRef = useRef<THREE.Mesh>(null);

  // iris
  const irisMat = useRef<THREE.ShaderMaterial>(null);
  const bladesRef = useRef<THREE.InstancedMesh>(null);
  const bladeGroup = useRef<THREE.Group>(null);

  // scan sweep
  const sweepRef = useRef<THREE.Group>(null);
  const sweepBar = useRef<THREE.Mesh>(null);
  const sweepTip = useRef<THREE.Mesh>(null);

  // lens outline + chest window brackets
  const rimMat = useRef<THREE.MeshBasicMaterial>(null);
  const rim2Mat = useRef<THREE.MeshBasicMaterial>(null);
  const bracketRefs = useRef<(THREE.Group | null)[]>([]);

  // probes + target orbs
  const streakRef = useRef<THREE.InstancedMesh>(null);
  const headRef = useRef<THREE.InstancedMesh>(null);
  const orbRefs = useRef<(THREE.Mesh | null)[]>([]);
  const orbMats = useRef<(THREE.MeshStandardMaterial | null)[]>([]);
  const ringRefs = useRef<(THREE.Mesh | null)[]>([]);
  const ringMats = useRef<(THREE.MeshBasicMaterial | null)[]>([]);

  // ---- scratch (zero per-frame allocation) -------------------------------
  const dummy = useMemo(() => new THREE.Object3D(), []);
  const tmpC = useMemo(() => new THREE.Color(), []);
  const vA = useMemo(() => new THREE.Vector3(), []);
  const vB = useMemo(() => new THREE.Vector3(), []);
  const vD = useMemo(() => new THREE.Vector3(), []);
  const quat = useMemo(() => new THREE.Quaternion(), []);
  const UP = useMemo(() => new THREE.Vector3(0, 1, 0), []);
  const PUPIL_POS = useMemo(() => new THREE.Vector3(0, 0, IRIS_Z + 0.05), []);

  // orb world positions, recomputed each frame into preallocated vectors
  const orbPos = useMemo(
    () => Array.from({ length: N_ORBS }, () => new THREE.Vector3()),
    []
  );
  // per-orb flash accumulator: [intensity, isFinding]
  const orbFlash = useMemo(() => new Float32Array(N_ORBS * 2), []);

  // deterministic orbit parameters (fixed once, no randomness at runtime)
  const orbits = useMemo(
    () =>
      Array.from({ length: N_ORBS }, (_, i) => {
        const h = hash32(i * 2654435761);
        return {
          radius: 3.95 + ((h >>> 3) % 100) / 100 * 0.95,
          tilt: 0.42 + ((h >>> 11) % 100) / 100 * 0.8,
          phase: (((h >>> 19) % 1000) / 1000) * TAU,
          speed: 0.11 + ((h >>> 5) % 100) / 100 * 0.09,
          dir: i % 2 === 0 ? 1 : -1,
          yOff: -0.35 + ((h >>> 23) % 100) / 100 * 0.7,
        };
      }),
    []
  );

  // iris blade layout (angle, inner/outer radius, hue mix, flicker phase)
  const blades = useMemo(() => {
    const a = new Float32Array(N_IRIS * 5);
    for (let i = 0; i < N_IRIS; i++) {
      const h = hash32(i * 40503 + 7);
      const j0 = ((h >>> 2) % 1000) / 1000;
      const j1 = ((h >>> 12) % 1000) / 1000;
      a[i * 5] = (i / N_IRIS) * TAU; // angle
      a[i * 5 + 1] = 0.46 + j0 * 0.14; // inner radius
      a[i * 5 + 2] = 1.16 + j1 * 0.14; // outer radius
      a[i * 5 + 3] = j0 * 0.65 + j1 * 0.35; // crimson↔amber mix
      a[i * 5 + 4] = (((h >>> 21) % 1000) / 1000) * TAU; // flicker phase
    }
    return a;
  }, []);

  // lens outline tubes (built from the lid maths, swept procedurally)
  const rimGeo = useMemo(() => {
    const curve = new THREE.CatmullRomCurve3(lensLoop(1), true, "centripetal", 0.5);
    return new THREE.TubeGeometry(curve, 260, 0.028, 5, true);
  }, []);
  const rimGeo2 = useMemo(() => {
    const curve = new THREE.CatmullRomCurve3(lensLoop(1.085), true, "centripetal", 0.5);
    return new THREE.TubeGeometry(curve, 200, 0.014, 4, true);
  }, []);
  // dark sclera backing: the same almond, filled, so the eye reads as a
  // silhouette against the starfield instead of letting stars shine through.
  const scleraGeo = useMemo(() => {
    const pts2 = lensLoop(0.985).map((p) => new THREE.Vector2(p.x, p.y));
    return new THREE.ShapeGeometry(new THREE.Shape(pts2));
  }, []);

  const irisUniforms = useMemo(
    () => ({
      uTime: { value: 0 },
      uScan: { value: 0 },
      uPupil: { value: PUPIL_R },
      uTension: { value: 0 },
    }),
    []
  );

  // mutable animation state (never reallocated)
  const st = useMemo(
    () => ({ tension: 0, lastCycle: new Int32Array(N_CH).fill(-1) }),
    []
  );

  useFrame(({ clock }, rawDelta) => {
    const dt = Math.min(rawDelta, 1 / 30);
    const ts = reduced ? 0.12 : 1; // reduced motion → very slow, never strobing
    const fast = reduced ? 0 : 1; // gates every high-frequency term
    const t = clock.elapsedTime * ts;

    // ================= overall drift (the composition never sits still) ====
    if (root.current) {
      root.current.rotation.y = 0.1 * Math.sin(t * 0.07) + 0.03 * Math.sin(t * 0.19 + 1.2);
      root.current.rotation.x = 0.05 * Math.sin(t * 0.05 + 1.0);
      root.current.position.y = 0.1 * Math.sin(t * 0.11);
    }
    if (eye.current) {
      const breath = 1 + 0.012 * Math.sin(t * 0.13);
      eye.current.scale.setScalar(breath);
      eye.current.rotation.z = 0.012 * Math.sin(t * 0.09 + 0.7);
    }

    // ================= probe channels (deterministic sequence) =============
    // Resolved first: the pupil and iris react to what the probes find.
    orbFlash.fill(0);
    let tension = 0;

    // orb orbits
    for (let i = 0; i < N_ORBS; i++) {
      const o = orbits[i];
      const a = o.phase + t * o.speed * o.dir;
      const ct = Math.cos(o.tilt);
      const stl = Math.sin(o.tilt);
      orbPos[i].set(
        o.radius * Math.cos(a),
        o.radius * Math.sin(a) * ct * 0.62 + o.yOff,
        o.radius * Math.sin(a) * stl
      );
    }

    for (let c = 0; c < N_CH; c++) {
      const off = (c * P_PERIOD) / N_CH;
      const local = (t + off) % P_PERIOD;
      const cycle = Math.floor((t + off) / P_PERIOD);
      const h = hash32(cycle * 7919 + c * 104729);
      const target = h % N_ORBS;
      const finding = ((h >>> 8) % FINDING_MOD) === 5;
      const tgt = orbPos[target];

      // --- verdict edge (fires once per arrival, off the hot path) --------
      if (local >= P_OUT && st.lastCycle[c] !== cycle) {
        st.lastCycle[c] = cycle;
        onVerdict?.(
          finding
            ? `${TARGETS[target]} · FINDING · signed`
            : `${TARGETS[target]} · contract held`,
          finding ? "finding" : "held"
        );
      }

      // --- orb flash -----------------------------------------------------
      if (local >= P_OUT && local < P_OUT + P_FLASH) {
        const f = 1 - (local - P_OUT) / P_FLASH;
        const cur = orbFlash[target * 2];
        if (f > cur) {
          orbFlash[target * 2] = f;
          orbFlash[target * 2 + 1] = finding ? 1 : 0;
        }
        if (finding) tension = Math.max(tension, f);
      }

      // --- streak + head -------------------------------------------------
      let show = true;
      let headE = 0;
      let from = PUPIL_POS;
      let to = tgt;
      if (local < P_OUT) {
        headE = smoothstep(0, 1, local / P_OUT); // outbound
      } else if (local >= P_BACK_T0 && local <= P_BACK_T1) {
        from = tgt;
        to = PUPIL_POS;
        headE = smoothstep(0, 1, (local - P_BACK_T0) / (P_BACK_T1 - P_BACK_T0));
      } else {
        show = false;
      }

      if (streakRef.current && headRef.current) {
        if (show) {
          const tailE = Math.max(0, headE - 0.17);
          vA.copy(from).lerp(to, headE); // head
          vB.copy(from).lerp(to, tailE); // tail
          vD.subVectors(vA, vB);
          const len = vD.length();
          if (len > 1e-4) {
            quat.setFromUnitVectors(UP, vD.divideScalar(len));
            dummy.position.addVectors(vA, vB).multiplyScalar(0.5);
            dummy.quaternion.copy(quat);
            dummy.scale.set(0.032, len, 0.032);
          } else {
            dummy.position.copy(vA);
            dummy.quaternion.identity();
            dummy.scale.set(0.032, 0.02, 0.032);
          }
          dummy.updateMatrix();
          streakRef.current.setMatrixAt(c, dummy.matrix);

          const outbound = local < P_OUT;
          if (outbound) tmpC.copy(ROSE).lerp(CRIMSON, headE);
          else tmpC.copy(finding ? CRIMSON : GREEN);
          tmpC.multiplyScalar(1.15 + 0.35 * Math.sin(t * 9 + c) * fast);
          streakRef.current.setColorAt(c, tmpC);

          dummy.position.copy(vA);
          dummy.quaternion.identity();
          dummy.scale.setScalar(0.075 + 0.02 * Math.sin(t * 7 + c * 2) * fast);
          dummy.updateMatrix();
          headRef.current.setMatrixAt(c, dummy.matrix);
          headRef.current.setColorAt(c, tmpC.multiplyScalar(1.25));
        } else {
          dummy.position.set(0, 0, 0);
          dummy.quaternion.identity();
          dummy.scale.setScalar(0.0001);
          dummy.updateMatrix();
          streakRef.current.setMatrixAt(c, dummy.matrix);
          headRef.current.setMatrixAt(c, dummy.matrix);
        }
      }
    }
    if (streakRef.current) {
      streakRef.current.instanceMatrix.needsUpdate = true;
      if (streakRef.current.instanceColor) streakRef.current.instanceColor.needsUpdate = true;
    }
    if (headRef.current) {
      headRef.current.instanceMatrix.needsUpdate = true;
      if (headRef.current.instanceColor) headRef.current.instanceColor.needsUpdate = true;
    }

    // the eye's involuntary tell: tension rises fast on a finding, decays slow
    const kUp = 1 - Math.exp(-dt * 9);
    const kDn = 1 - Math.exp(-dt * 1.1);
    st.tension += (tension - st.tension) * (tension > st.tension ? kUp : kDn);

    // ================= target orbs =========================================
    for (let i = 0; i < N_ORBS; i++) {
      const m = orbRefs.current[i];
      const mat = orbMats.current[i];
      const f = orbFlash[i * 2];
      const isFind = orbFlash[i * 2 + 1] > 0.5;
      if (m) {
        m.position.copy(orbPos[i]);
        m.scale.setScalar(0.16 * (1 + f * 1.5));
        m.rotation.y = t * 0.5;
        m.rotation.x = t * 0.23;
      }
      if (mat) {
        if (f > 0) tmpC.copy(isFind ? CRIMSON : GREEN);
        else tmpC.copy(IDLE);
        mat.color.copy(tmpC);
        mat.emissive.copy(tmpC);
        mat.emissiveIntensity = 0.55 + f * 4.2;
      }
      const ring = ringRefs.current[i];
      const rmat = ringMats.current[i];
      if (ring && rmat) {
        ring.position.copy(orbPos[i]);
        ring.rotation.set(Math.PI / 2.6, t * 0.4 + i, 0);
        if (f > 0) {
          const e = 1 - f; // 0 at arrival → 1 as the flash dies
          ring.scale.setScalar(0.22 + e * 0.95);
          rmat.color.copy(isFind ? CRIMSON : GREEN);
          rmat.opacity = f * 0.85;
        } else {
          ring.scale.setScalar(0.0001);
          rmat.opacity = 0;
        }
      }
    }

    // ================= pupil: breathing dilation ===========================
    // incommensurate periods → a rhythm, not a loop; tension constricts it.
    const dil =
      1 +
      0.055 * Math.sin(t * 0.62) +
      0.032 * Math.sin(t * 1.31 + 1.1) +
      0.018 * Math.sin(t * 2.17 + 2.4) -
      0.16 * st.tension;
    const pr = PUPIL_R * dil;
    if (pupilRef.current) {
      pupilRef.current.scale.set(dil, dil, dil * 0.62);
      pupilRef.current.rotation.z = -t * 0.06; // counter-rotates the iris
    }
    if (pupilMat.current) {
      pupilMat.current.emissiveIntensity = 0.25 + st.tension * 1.6;
      tmpC.copy(CRIMSON).lerp(WHITE, st.tension * 0.35);
      pupilMat.current.emissive.copy(tmpC);
    }
    if (glowRef.current && glowMat.current) {
      glowRef.current.scale.set(dil * 1.22, dil * 1.22, dil * 0.8);
      glowMat.current.opacity = 0.1 + 0.05 * Math.sin(t * 0.9) + st.tension * 0.22;
      tmpC.copy(AMBER).lerp(CRIMSON, 0.5 + 0.5 * Math.sin(t * 0.35));
      glowMat.current.color.copy(tmpC);
    }
    if (catchRef.current) {
      // specular catchlight — the thing that makes an eye read as alive
      catchRef.current.position.set(
        -0.17 + 0.012 * Math.sin(t * 0.5),
        0.18 + 0.01 * Math.cos(t * 0.43),
        IRIS_Z + 0.24
      );
      catchRef.current.scale.setScalar(0.055 + 0.006 * Math.sin(t * 1.7) * fast);
    }

    // ================= iris: shader + counter-rotating blades ==============
    const scan = (t * 0.42) % TAU; // the sweep angle (slow period ≈ 15 s)
    if (irisMat.current) {
      irisMat.current.uniforms.uTime.value = t;
      irisMat.current.uniforms.uScan.value = scan;
      irisMat.current.uniforms.uPupil.value = pr;
      irisMat.current.uniforms.uTension.value = st.tension;
    }
    if (bladeGroup.current) bladeGroup.current.rotation.z = t * 0.045;
    if (bladesRef.current) {
      for (let i = 0; i < N_IRIS; i++) {
        const a = blades[i * 5];
        const r0 = Math.max(blades[i * 5 + 1], pr + 0.02);
        const r1 = blades[i * 5 + 2];
        const mix = blades[i * 5 + 3];
        const ph = blades[i * 5 + 4];
        const len = Math.max(0.02, r1 - r0);
        const rm = (r0 + r1) * 0.5;
        dummy.position.set(Math.cos(a) * rm, Math.sin(a) * rm, IRIS_Z + 0.035);
        dummy.rotation.set(0, 0, a);
        dummy.scale.set(len, 0.02 + 0.012 * mix, 0.012);
        dummy.updateMatrix();
        bladesRef.current.setMatrixAt(i, dummy.matrix);

        // brightened by the sweep it has just passed (matches the shader trail)
        let d = ((a + (bladeGroup.current?.rotation.z ?? 0) - scan + Math.PI) % TAU + TAU) % TAU - Math.PI;
        const lead = Math.exp(-((d / 0.2) * (d / 0.2)));
        const trail = d < 0.02 ? Math.exp(Math.max(-7, d * 2.4)) : 0;
        const boost = 1 + lead * 2.6 + trail * 0.9;
        tmpC.copy(CRIMSON).lerp(AMBER, mix);
        tmpC.multiplyScalar((0.32 + 0.3 * (0.5 + 0.5 * Math.sin(t * 1.3 + ph) * fast)) * boost);
        if (st.tension > 0.02) tmpC.lerp(WHITE, st.tension * 0.25);
        bladesRef.current.setColorAt(i, tmpC);
      }
      bladesRef.current.instanceMatrix.needsUpdate = true;
      if (bladesRef.current.instanceColor) bladesRef.current.instanceColor.needsUpdate = true;
    }

    // ================= the scan sweep blade ================================
    if (sweepRef.current) sweepRef.current.rotation.z = scan;
    if (sweepBar.current) {
      const mid = (pr + 0.06 + IRIS_OUT) * 0.5;
      sweepBar.current.position.set(mid, 0, IRIS_Z + 0.075);
      sweepBar.current.scale.set(IRIS_OUT - pr - 0.06, 0.05 + 0.012 * Math.sin(t * 3) * fast, 0.012);
      (sweepBar.current.material as THREE.MeshBasicMaterial).opacity =
        0.75 + 0.25 * Math.sin(t * 2.2) * fast;
    }
    if (sweepTip.current) {
      sweepTip.current.position.set(IRIS_OUT - 0.02, 0, IRIS_Z + 0.08);
      sweepTip.current.scale.setScalar(0.07 + 0.02 * Math.sin(t * 4.1) * fast);
    }

    // ================= lens rim + chest-window brackets ====================
    if (rimMat.current) {
      tmpC.copy(CRIMSON).lerp(AMBER, 0.35 + 0.25 * Math.sin(t * 0.4));
      rimMat.current.color.copy(tmpC).multiplyScalar(1.5 + st.tension * 0.9);
    }
    if (rim2Mat.current) {
      rim2Mat.current.opacity = 0.3 + 0.12 * Math.sin(t * 0.31 + 1.0);
    }
    for (let i = 0; i < 4; i++) {
      const g = bracketRefs.current[i];
      if (!g) continue;
      const sx = i === 0 || i === 3 ? -1 : 1;
      const sy = i < 2 ? 1 : -1;
      g.position.set(
        sx * (W * 1.17 + 0.07 * Math.sin(t * 0.37 + i)),
        sy * (2.16 + 0.06 * Math.cos(t * 0.29 + i * 1.7)),
        1.35 + 0.1 * Math.sin(t * 0.23 + i * 2.1)
      );
      g.rotation.z = 0.02 * Math.sin(t * 0.33 + i);
    }
  });

  return (
    <group ref={root}>
      {/* ===================== THE EYE ===================== */}
      <group ref={eye}>
        {/* dark sclera backing — makes the almond silhouette read */}
        <mesh geometry={scleraGeo} position={[0, 0, -0.35]}>
          <meshBasicMaterial color="#0a0410" transparent opacity={0.72} depthWrite={false} />
        </mesh>

        {/* glowing almond lens outline (procedural lid arcs → tube) */}
        <mesh geometry={rimGeo}>
          <meshBasicMaterial
            ref={rimMat}
            color={CRIMSON}
            toneMapped={false}
            transparent
            opacity={0.95}
            blending={THREE.AdditiveBlending}
            depthWrite={false}
          />
        </mesh>
        <mesh geometry={rimGeo2}>
          <meshBasicMaterial
            ref={rim2Mat}
            color={AMBER}
            toneMapped={false}
            transparent
            opacity={0.35}
            blending={THREE.AdditiveBlending}
            depthWrite={false}
          />
        </mesh>

        {/* iris body — procedural fibre shader with the sweep baked in */}
        <mesh position={[0, 0, IRIS_Z]}>
          <ringGeometry args={[IRIS_IN, IRIS_OUT, 128, 2]} />
          <shaderMaterial
            ref={irisMat}
            vertexShader={IRIS_VERT}
            fragmentShader={IRIS_FRAG}
            uniforms={irisUniforms}
            transparent
            blending={THREE.AdditiveBlending}
            depthWrite={false}
            toneMapped={false}
            side={THREE.DoubleSide}
          />
        </mesh>

        {/* iris blades — many thin instanced radial elements */}
        <group ref={bladeGroup}>
          <instancedMesh
            ref={bladesRef as any}
            args={[undefined as any, undefined as any, N_IRIS]}
            frustumCulled={false}
          >
            <boxGeometry args={[1, 1, 1]} />
            <meshBasicMaterial
              vertexColors
              toneMapped={false}
              transparent
              opacity={0.9}
              blending={THREE.AdditiveBlending}
              depthWrite={false}
            />
          </instancedMesh>
        </group>

        {/* scan sweep — bright blade + tip, rotating through the iris */}
        <group ref={sweepRef}>
          <mesh ref={sweepBar}>
            <boxGeometry args={[1, 1, 1]} />
            <meshBasicMaterial
              color="#fff0f2"
              toneMapped={false}
              transparent
              opacity={0.85}
              blending={THREE.AdditiveBlending}
              depthWrite={false}
            />
          </mesh>
          <mesh ref={sweepTip}>
            <sphereGeometry args={[1, 12, 10]} />
            <meshBasicMaterial
              color="#ffd9c9"
              toneMapped={false}
              transparent
              opacity={0.95}
              blending={THREE.AdditiveBlending}
              depthWrite={false}
            />
          </mesh>
        </group>

        {/* pupil dome + inner glow + catchlight */}
        <mesh ref={pupilRef} position={[0, 0, IRIS_Z]}>
          <sphereGeometry args={[PUPIL_R, 40, 28]} />
          <meshStandardMaterial
            ref={pupilMat}
            color="#0b0208"
            emissive={CRIMSON}
            emissiveIntensity={0.3}
            roughness={0.28}
            metalness={0.55}
          />
        </mesh>
        <mesh ref={glowRef} position={[0, 0, IRIS_Z]}>
          <sphereGeometry args={[PUPIL_R, 24, 18]} />
          <meshBasicMaterial
            ref={glowMat}
            color={AMBER}
            toneMapped={false}
            transparent
            opacity={0.14}
            blending={THREE.AdditiveBlending}
            depthWrite={false}
            side={THREE.BackSide}
          />
        </mesh>
        <mesh ref={catchRef}>
          <sphereGeometry args={[1, 12, 10]} />
          <meshBasicMaterial
            color="#fff6f8"
            toneMapped={false}
            transparent
            opacity={0.9}
            blending={THREE.AdditiveBlending}
            depthWrite={false}
          />
        </mesh>
      </group>

      {/* ===================== CHEST-WINDOW FRAME ===================== */}
      {[0, 1, 2, 3].map((i) => {
        const sx = i === 0 || i === 3 ? -1 : 1;
        const sy = i < 2 ? 1 : -1;
        return (
          <group key={i} ref={(el) => (bracketRefs.current[i] = el)}>
            <mesh position={[(sx * 0.62) / 2, 0, 0]}>
              <boxGeometry args={[0.62, 0.045, 0.045]} />
              <meshBasicMaterial
                color={AMBER}
                toneMapped={false}
                transparent
                opacity={0.7}
                blending={THREE.AdditiveBlending}
                depthWrite={false}
              />
            </mesh>
            <mesh position={[0, (sy * 0.52) / 2, 0]}>
              <boxGeometry args={[0.045, 0.52, 0.045]} />
              <meshBasicMaterial
                color={AMBER}
                toneMapped={false}
                transparent
                opacity={0.7}
                blending={THREE.AdditiveBlending}
                depthWrite={false}
              />
            </mesh>
          </group>
        );
      })}

      {/* ===================== TARGET ORBS + FLASH RINGS ===================== */}
      {Array.from({ length: N_ORBS }, (_, i) => (
        <group key={i}>
          <mesh ref={(el) => (orbRefs.current[i] = el)}>
            <icosahedronGeometry args={[1, 2]} />
            <meshStandardMaterial
              ref={(el) => (orbMats.current[i] = el)}
              color={IDLE}
              emissive={IDLE}
              emissiveIntensity={0.6}
              roughness={0.35}
              metalness={0.3}
              toneMapped={false}
            />
          </mesh>
          <mesh ref={(el) => (ringRefs.current[i] = el)}>
            <torusGeometry args={[1, 0.045, 6, 40]} />
            <meshBasicMaterial
              ref={(el) => (ringMats.current[i] = el)}
              color={GREEN}
              toneMapped={false}
              transparent
              opacity={0}
              blending={THREE.AdditiveBlending}
              depthWrite={false}
            />
          </mesh>
        </group>
      ))}

      {/* ===================== PROBE BEAMS ===================== */}
      <instancedMesh
        ref={streakRef as any}
        args={[undefined as any, undefined as any, N_CH]}
        frustumCulled={false}
      >
        <boxGeometry args={[1, 1, 1]} />
        <meshBasicMaterial
          vertexColors
          toneMapped={false}
          transparent
          opacity={0.9}
          blending={THREE.AdditiveBlending}
          depthWrite={false}
        />
      </instancedMesh>
      <instancedMesh
        ref={headRef as any}
        args={[undefined as any, undefined as any, N_CH]}
        frustumCulled={false}
      >
        <sphereGeometry args={[1, 12, 10]} />
        <meshBasicMaterial
          vertexColors
          toneMapped={false}
          transparent
          opacity={0.95}
          blending={THREE.AdditiveBlending}
          depthWrite={false}
        />
      </instancedMesh>
    </group>
  );
}
