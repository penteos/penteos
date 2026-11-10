import { Markdown } from "../ui/Markdown";

/** A long agent answer, opened full width in the editor area. */
export function DocPanel(props: { params: { markdown: string } }) {
  return (
    <div className="panel">
      <div className="panel-scroll">
        <div className="doc turn-agent">
          <Markdown text={props.params.markdown} />
        </div>
      </div>
    </div>
  );
}
