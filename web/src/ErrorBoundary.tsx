import { Component, ErrorInfo, ReactNode } from "react";

// Without a boundary, any render-time throw unmounts the whole tree and the UI
// vanishes with no explanation. This keeps the shell up and shows the error.
export default class ErrorBoundary extends Component<
  { children: ReactNode },
  { error: Error | null }
> {
  state = { error: null as Error | null };

  static getDerivedStateFromError(error: Error) {
    return { error };
  }

  componentDidCatch(error: Error, info: ErrorInfo) {
    console.error("UI error:", error, info);
  }

  render() {
    if (this.state.error) {
      return (
        <div style={{ padding: 24 }}>
          <h2 className="sev-high">Something broke in the UI</h2>
          <div className="pre">{String(this.state.error)}</div>
          <p className="muted">Check the browser console for the full stack.</p>
          <button onClick={() => this.setState({ error: null })}>Try again</button>
        </div>
      );
    }
    return this.props.children;
  }
}
