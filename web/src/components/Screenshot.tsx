import { useState } from "react";
import { Modal } from "./ui";
import { api } from "../api";

/**
 * Viewer for a service's screenshot.
 *
 * The image is served by our own API rather than straight from object storage:
 * the app's CSP allows images from 'self' only, and a presigned store URL would
 * be a bearer token for that object embedded in the page.
 */
export function ScreenshotModal({
  serviceID, title, onClose,
}: { serviceID: string; title: string; onClose: () => void }) {
  const [state, setState] = useState<"loading" | "ok" | "error">("loading");

  return (
    <Modal
      title={title}
      open
      onClose={onClose}
      wide
      footer={<button className="ghost" onClick={onClose}>Close</button>}
    >
      {state === "error" ? (
        <div className="empty">
          The screenshot is recorded but could not be loaded. It may have been
          removed from artifact storage since the scan.
        </div>
      ) : (
        <div style={{ textAlign: "center" }}>
          {state === "loading" && (
            <div className="muted" style={{ padding: 12 }}>Loading screenshot…</div>
          )}
          <img
            src={api.screenshotURL(serviceID)}
            alt={`Screenshot of ${title}`}
            onLoad={() => setState("ok")}
            onError={() => setState("error")}
            style={{
              maxWidth: "100%", height: "auto", borderRadius: 6,
              display: state === "ok" ? "block" : "none",
              border: "1px solid var(--border, rgba(127,127,127,.3))",
            }}
          />
        </div>
      )}
    </Modal>
  );
}

/**
 * Button that opens the viewer. Clicks are kept to itself: in the Hosts table
 * the surrounding row opens the host page, and neither the button nor anything
 * in the dialog should trigger that.
 */
export function ScreenshotButton({
  serviceID, title, label = "Screenshot",
}: { serviceID: string; title: string; label?: string }) {
  const [open, setOpen] = useState(false);
  return (
    <span onClick={(e) => e.stopPropagation()}>
      <button
        className="ghost sm"
        title="View the screenshot captured for this service"
        onClick={() => setOpen(true)}
      >
        ▣ {label}
      </button>
      {open && (
        <ScreenshotModal serviceID={serviceID} title={title} onClose={() => setOpen(false)} />
      )}
    </span>
  );
}
