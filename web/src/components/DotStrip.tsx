import { FindingRun } from "../api";

/**
 * A finding's history as one dot per run that could have seen it, oldest on
 * the left: filled when that run observed it, hollow when it looked and did
 * not. Hovering a dot shows when that run happened and, if it saw the finding,
 * the severity it reported — so a gap or a severity change is readable
 * without leaving the table.
 */
export function DotStrip({ history, max = 24 }: { history: FindingRun[]; max?: number }) {
  if (history.length === 0) {
    return <span className="muted" style={{ fontSize: 11 }}>not re-checked yet</span>;
  }
  const shown = history.length > max ? history.slice(history.length - max) : history;
  const hidden = history.length - shown.length;
  return (
    <span className="dotstrip" aria-label={`${history.filter((h) => h.observed).length} of ${history.length} runs`}>
      {hidden > 0 && <span className="muted" style={{ fontSize: 10, marginRight: 4 }}>+{hidden}</span>}
      {shown.map((h) => {
        const when = new Date(h.at).toLocaleString();
        const tip = h.observed
          ? `Seen ${when}${h.severity ? ` · ${h.severity}` : ""}`
          : `Not found ${when}`;
        return (
          <span
            key={h.run_id}
            className={"dot" + (h.observed ? " dot-on" : " dot-off")}
            title={tip}
            data-tip={tip}
          />
        );
      })}
    </span>
  );
}

/** active / gone since <date>, from the fields the API derives. */
export function PresenceBadge({ presence, goneSince }: { presence?: string; goneSince?: string | null }) {
  if (presence === "gone") {
    const since = goneSince ? new Date(goneSince).toLocaleDateString() : "";
    return <span className="badge b-gone" title={goneSince ? `Not seen since ${new Date(goneSince).toLocaleString()}` : undefined}>gone{since ? ` · ${since}` : ""}</span>;
  }
  return <span className="badge b-open">active</span>;
}
