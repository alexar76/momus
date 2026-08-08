import { ReactNode, useEffect, useMemo, useRef, useState } from "react";
import { Canvas, useFrame } from "@react-three/fiber";
import { OrbitControls, Sparkles, Stars } from "@react-three/drei";
import { Bloom, EffectComposer, Vignette } from "@react-three/postprocessing";
import * as THREE from "three";

/* ===========================================================================
 *  CosmicCanvas — the shared deep-space stage for the MOMUS eye scene.
 *
 *  Adapted from the GAIA / oracle-family CosmicCanvas so MOMUS renders in the
 *  exact same visual language as the rest of the ecosystem: a procedural fbm
 *  nebula sphere, two layered starfields, drifting sparkles, three coloured key
 *  lights, and a Bloom + Vignette post stack. The signature scene mounts as
 *  `children`.
 *
 *  The ONE family deviation: the third key light is MOMUS crimson (#ff2d55)
 *  instead of the family amber, so the eye is lit from the front in its own
 *  accent. The nebula itself is untouched deep purple / cyan / magenta — that
 *  shared backdrop is the whole point of the shared stage.
 *
 *  Everything is procedural: no models, textures, HDRIs or fonts are loaded,
 *  and the component makes no network requests of any kind.
 * ========================================================================= */

// Procedural fbm nebula backdrop (the cosmic signature of the family).
const NEBULA_VERT = `
varying vec3 vDir;
void main(){ vDir = normalize(position); gl_Position = projectionMatrix * modelViewMatrix * vec4(position,1.0); }
`;
const NEBULA_FRAG = `
precision highp float;
varying vec3 vDir; uniform float uTime;
float hash(vec3 p){ p=fract(p*0.3183099+0.1); p*=17.0; return fract(p.x*p.y*p.z*(p.x+p.y+p.z)); }
float noise(vec3 x){ vec3 i=floor(x),f=fract(x); f=f*f*(3.0-2.0*f);
  return mix(mix(mix(hash(i+vec3(0,0,0)),hash(i+vec3(1,0,0)),f.x),mix(hash(i+vec3(0,1,0)),hash(i+vec3(1,1,0)),f.x),f.y),
             mix(mix(hash(i+vec3(0,0,1)),hash(i+vec3(1,0,1)),f.x),mix(hash(i+vec3(0,1,1)),hash(i+vec3(1,1,1)),f.x),f.y),f.z); }
float fbm(vec3 p){ float v=0.0,a=0.5; for(int i=0;i<5;i++){ v+=a*noise(p); p*=2.02; a*=0.5; } return v; }
void main(){
  vec3 d=normalize(vDir); float t=uTime*0.015; vec3 p=d*2.2+vec3(t,t*0.5,-t*0.3);
  float n=fbm(p); float clouds=smoothstep(0.42,0.95,n);
  vec3 deep=vec3(0.012,0.012,0.045), purple=vec3(0.18,0.07,0.34), cyan=vec3(0.10,0.45,0.62), magenta=vec3(0.46,0.12,0.42);
  vec3 col=deep; col=mix(col,purple,clouds*0.85);
  float hi=smoothstep(0.6,1.0,fbm(p*1.7+5.0)); col=mix(col,cyan,hi*0.5*clouds);
  col=mix(col,magenta,smoothstep(0.72,1.0,n)*0.4);
  float band=exp(-pow(d.y*2.4,2.0))*0.14; col+=vec3(0.20,0.26,0.42)*band;
  gl_FragColor=vec4(col,1.0);
}
`;

function Nebula({ timeScale = 1 }: { timeScale?: number }) {
  const matRef = useRef<THREE.ShaderMaterial>(null);
  const uniforms = useMemo(() => ({ uTime: { value: 0 } }), []);
  useFrame(({ clock }) => {
    if (matRef.current) matRef.current.uniforms.uTime.value = clock.elapsedTime * timeScale;
  });
  return (
    <mesh renderOrder={-10}>
      <sphereGeometry args={[92, 48, 48]} />
      <shaderMaterial ref={matRef} vertexShader={NEBULA_VERT} fragmentShader={NEBULA_FRAG}
        uniforms={uniforms} side={THREE.BackSide} depthWrite={false} fog={false} />
    </mesh>
  );
}

/** `true` when the visitor asked for reduced motion (live-updating). */
export function usePrefersReducedMotion(): boolean {
  const [reduced, setReduced] = useState(() => {
    if (typeof window === "undefined" || !window.matchMedia) return false;
    return window.matchMedia("(prefers-reduced-motion: reduce)").matches;
  });
  useEffect(() => {
    if (typeof window === "undefined" || !window.matchMedia) return;
    const mq = window.matchMedia("(prefers-reduced-motion: reduce)");
    const onChange = () => setReduced(mq.matches);
    mq.addEventListener?.("change", onChange);
    return () => mq.removeEventListener?.("change", onChange);
  }, []);
  return reduced;
}

/** `true` on touch-first devices — there we hand every drag back to the page
 *  instead of letting OrbitControls trap the scroll gesture. */
export function useCoarsePointer(): boolean {
  const [coarse, setCoarse] = useState(() => {
    if (typeof window === "undefined" || !window.matchMedia) return false;
    return window.matchMedia("(pointer: coarse)").matches;
  });
  useEffect(() => {
    if (typeof window === "undefined" || !window.matchMedia) return;
    const mq = window.matchMedia("(pointer: coarse)");
    const onChange = () => setCoarse(mq.matches);
    mq.addEventListener?.("change", onChange);
    return () => mq.removeEventListener?.("change", onChange);
  }, []);
  return coarse;
}

export interface CosmicCanvasProps {
  children: ReactNode;
  camera?: [number, number, number];
  fov?: number;
  autoRotate?: boolean;
  autoRotateSpeed?: number;
  bloom?: number;
  controls?: boolean;
  /** Wheel-zoom is OFF by default: this canvas lives inside a scrolling landing
   *  page and must never hijack the page's scroll. */
  zoom?: boolean;
  /** Scales nebula/star drift; the scene scales its own motion separately. */
  timeScale?: number;
}

/** Shared cosmic environment (nebula + starfields + sparkles + bloom + lights).
 *  MOMUS renders its unblinking-eye scene as `children` inside this Canvas. */
export function CosmicCanvas({
  children,
  camera = [0, 0.5, 13],
  fov = 42,
  autoRotate = false,
  autoRotateSpeed = 0.18,
  bloom = 1.02,
  controls = true,
  zoom = false,
  timeScale = 1,
}: CosmicCanvasProps) {
  const slow = timeScale < 1;
  return (
    <Canvas camera={{ position: camera, fov }} dpr={[1, 2]}
      gl={{ antialias: true, alpha: false, powerPreference: "high-performance" }}>
      <color attach="background" args={["#04030f"]} />
      <fog attach="fog" args={["#04030f", 26, 72]} />
      <ambientLight intensity={0.15} />
      <pointLight position={[8, 10, 6]} intensity={2.4} color="#6ee7ff" />
      <pointLight position={[-6, 5, -4]} intensity={1.8} color="#c084fc" />
      {/* the one MOMUS deviation: front key light in crimson, not amber */}
      <pointLight position={[0, -3, 9]} intensity={1.5} color="#ff2d55" />
      <Nebula timeScale={timeScale} />
      <Stars radius={120} depth={60} count={6000} factor={4} fade speed={slow ? 0.05 : 0.6} />
      <Stars radius={60} depth={28} count={2400} factor={3} fade speed={slow ? 0.1 : 1.3} />
      <Sparkles count={160} scale={[22, 12, 22]} size={2} speed={slow ? 0.03 : 0.3} opacity={0.3} color="#6ee7ff" />
      <Sparkles count={110} scale={[28, 16, 28]} size={3.4} speed={slow ? 0.02 : 0.16} opacity={0.2} color="#ff8fb0" />
      {children}
      <EffectComposer multisampling={0}>
        <Bloom intensity={bloom} luminanceThreshold={0.3} luminanceSmoothing={0.82} mipmapBlur />
        <Vignette eskil offset={0.14} darkness={1.05} />
      </EffectComposer>
      {controls && (
        <OrbitControls enablePan={false} enableZoom={zoom} maxDistance={26} minDistance={6}
          autoRotate={autoRotate} autoRotateSpeed={autoRotateSpeed}
          minPolarAngle={Math.PI * 0.22} maxPolarAngle={Math.PI * 0.78}
          minAzimuthAngle={-Math.PI * 0.32} maxAzimuthAngle={Math.PI * 0.32} />
      )}
    </Canvas>
  );
}
