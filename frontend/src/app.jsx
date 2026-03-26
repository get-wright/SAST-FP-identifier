import Router from "preact-router";

function Setup() { return <main><h1>Setup</h1></main>; }
function Analyzing() { return <main><h1>Analyzing...</h1></main>; }
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
