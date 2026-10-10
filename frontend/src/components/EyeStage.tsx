import { CosmicCanvas, useCoarsePointer, usePrefersReducedMotion } from "../CosmicCanvas";
import MomusScene from "../scenes/momus";

/* ===========================================================================
 *  EyeStage — the MOMUS hero stage: the signature eye scene mounted inside the
 *  ecosystem's shared cosmic canvas.
 *
 *  Loaded lazily by Hero so three.js lands in its own chunk and the landing
 *  copy paints without waiting for the renderer.
 * ========================================================================= */

export interface EyeStageProps {
  onVerdict?: (text: string, kind: "held" | "finding") => void;
}

export default function EyeStage({ onVerdict }: EyeStageProps) {
  const reduced = usePrefersReducedMotion();
  const coarse = useCoarsePointer();
  return (
    <CosmicCanvas
      camera={[0, 0.45, 13]}
      fov={42}
      bloom={reduced ? 0.85 : 1.05}
      timeScale={reduced ? 0.12 : 1}
      // On touch devices OrbitControls would swallow the page-scroll gesture,
      // so the stage is look-only there. Wheel-zoom is off everywhere.
      controls={!coarse}
      zoom={false}
    >
      <MomusScene onVerdict={onVerdict} reduced={reduced} />
    </CosmicCanvas>
  );
}
