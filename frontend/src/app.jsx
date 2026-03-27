import Router from "preact-router";
import { Setup } from "./pages/Setup";
import { Analyzing } from "./pages/Analyzing";
import { Results } from "./pages/Results";

export function App() {
  return (
    <Router>
      <Setup path="/" />
      <Analyzing path="/analyzing" />
      <Results path="/results" />
    </Router>
  );
}
