import Router from "preact-router";
import { Setup } from "./pages/Setup";
import { Analyzing } from "./pages/Analyzing";

function Results() { return <main><h1>Results</h1></main>; }

export function App() {
  return (
    <Router>
      <Setup path="/" />
      <Analyzing path="/analyzing" />
      <Results path="/results" />
    </Router>
  );
}
