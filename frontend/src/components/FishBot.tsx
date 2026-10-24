import type { Mood } from "../lib/fishbot";

const LABEL: Record<Mood, string> = {
  idle: "FishBot idle",
  analyzing: "FishBot analyzing",
  alert: "FishBot alert",
  happy: "FishBot happy",
  curious: "FishBot curious",
  thinking: "FishBot thinking",
};

/** Original mascot. No external artwork. */
export function FishBot({ mood, size = 72 }: { mood: Mood; size?: number }) {
  const worried = mood === "alert";
  const happy = mood === "happy";
  const curious = mood === "curious";
  const thinking = mood === "thinking";
  const pupil = worried ? 2.1 : 3.1;
  const leftPupil = curious ? "26,35" : thinking ? "29,34" : worried ? "29,40" : "29,38";
  const rightPupil = curious ? "43,34" : thinking ? "46,34" : worried ? "45,40" : "45,38";
  return (
    <svg
      className={`fish fish-${mood} fish-swim`}
      width={size}
      height={size}
      viewBox="0 0 80 80"
      role="img"
      aria-label={LABEL[mood]}
    >
      <ellipse cx="36" cy="44" rx="22" ry="16" className="fish-body" />
      <ellipse cx="34" cy="48" rx="12" ry="7" className="fish-belly" />
      <path d="M56 44 L74 28 L70 44 L74 60 Z" className="fish-tail" />
      <path d="M28 30 C34 18, 46 18, 50 32" className="fish-fin" />
      <path d="M22 50 C16 58, 28 64, 34 54" className="fish-fin" />
      <circle cx="28" cy="38" r="7" className="fish-eye" />
      <circle cx="44" cy="38" r="7" className="fish-eye" />
      <circle cx={leftPupil.split(",")[0]} cy={leftPupil.split(",")[1]} r={pupil} className="fish-pupil" />
      <circle cx={rightPupil.split(",")[0]} cy={rightPupil.split(",")[1]} r={pupil} className="fish-pupil" />
      <circle cx="26" cy="36" r="1.3" className="fish-shine" />
      <circle cx="42" cy="36" r="1.3" className="fish-shine" />
      {happy ? (
        <path d="M30 48 Q36 56 44 48" className="fish-mouth" />
      ) : worried ? (
        <path d="M30 52 Q36 46 44 52" className="fish-mouth" />
      ) : curious ? (
        <ellipse cx="36" cy="50" rx="3" ry="3.4" className="fish-mouth" />
      ) : (
        <path d="M31 49 Q36 53 42 49" className="fish-mouth" />
      )}
      {worried && <path d="M58 32 l3 6 l-3 1 z" className="fish-sweat" />}
      {thinking && (
        <g className="fish-dots">
          <circle cx="62" cy="22" r="1.4" />
          <circle cx="67" cy="18" r="1.8" />
          <circle cx="73" cy="14" r="2.2" />
        </g>
      )}
      {mood === "analyzing" && (
        <g className="fish-bubbles">
          <circle cx="64" cy="24" r="3" />
          <circle cx="72" cy="14" r="4" />
          <circle cx="58" cy="14" r="2" />
        </g>
      )}
    </svg>
  );
}
