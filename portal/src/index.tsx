// comment out next line for disabling axe
// /* global process */
// This following 2 lines are extremely important.
// Since we do not provide our babel.config.json,
// Parcel provides a default one for us.
// The default config uses preset-env with useBuiltins: entry.
// Therefore, we have to include the following imports to
// let Babel rewrite them into polyfill imports according to .browserslistrc.
import "core-js/stable";
import "regenerator-runtime/runtime";

import "normalize.css";
import "./index.scss";

import React from "react";
import { render } from "react-dom";
import {
  initializeIcons,
  Shade,
  getColorFromString,
  getShade,
  getBackgroundShade,
  mapEnumByName,
} from "@fluentui/react";

// import ReactApp from "./ReactApp";

initializeIcons();

/* NOTE: disabled axe as it does not work well with monaco editor
 *       screen with monaco editor is extremely slow

// Run axe every 3 seconds to discover accessibility issues.
// Ideally we should use react-axe instead but it has the following issue
// https://github.com/dequelabs/react-axe/issues/122
// making it useless in our setup.
// So we use axe-core directly with a periodic check.
if (process.env.NODE_ENV === "development") {
  // Use dynamic import so that parcel can exclude it from production build.
  import("axe-core").then(
    (axe) => {
      let violations: any[] = [];
      const checkAndReport = () => {
        axe.run().then(
          (results) => {
            const a = JSON.stringify(violations);
            const b = JSON.stringify(results.violations);
            if (a !== b) {
              violations = results.violations;
              if (violations.length > 0) {
                console.warn("axe violations", violations);
              } else {
                console.warn("axe violations are all cleared!");
              }
            }
          },
          (err) => console.error(err)
        );
      };

      checkAndReport();
      setInterval(checkAndReport, 3000);
    },
    (err) => {
      console.error(err);
    }
  );
}
*/
interface ColorPaletteProps {
  primary: string;
  foreground: string;
  background: string;
  darkMode?: boolean;
}

function ColorPalette(props: ColorPaletteProps) {
  const { primary, foreground, background, darkMode } = props;
  const primaryColor = getColorFromString(primary)!;
  const foregroundColor = getColorFromString(foreground)!;
  const backgroundColor = getColorFromString(background)!;

  const primaryShades = mapEnumByName(Shade, (_name, value) => {
    return getShade(primaryColor, value as Shade, darkMode);
  });
  const foregroundShades = mapEnumByName(Shade, (_name, value) => {
    return getShade(foregroundColor, value as Shade, darkMode);
  });
  const backgroundShades = mapEnumByName(Shade, (_name, value) => {
    return getBackgroundShade(backgroundColor, value as Shade, darkMode);
  });

  return (
    <div
      style={{
        display: "flex",
        flexDirection: "row",
      }}
    >
      <div>
        {primaryShades!.map((color) => {
          return (
            <div
              key={color!.str}
              style={{
                width: "50px",
                height: "50px",
                backgroundColor: color!.str,
              }}
            />
          );
        })}
      </div>
      <div>
        {foregroundShades!.map((color) => {
          return (
            <div
              key={color!.str}
              style={{
                width: "50px",
                height: "50px",
                backgroundColor: color!.str,
              }}
            />
          );
        })}
      </div>
      <div>
        {backgroundShades!.map((color) => {
          return (
            <div
              key={color!.str}
              style={{
                width: "50px",
                height: "50px",
                backgroundColor: color!.str,
              }}
            />
          );
        })}
      </div>
    </div>
  );
}

function ColorApp() {
  return (
    <div style={{ display: "flex", flexDirection: "row" }}>
      <ColorPalette
        primary={"#0078d4"}
        foreground={"#323130"}
        background={"#ffffff"}
      />
      <ColorPalette
        primary={"#e50914"}
        foreground={"#ffffff"}
        background={"#000000"}
        darkMode={true}
      />
    </div>
  );
}

render(<ColorApp />, document.getElementById("react-app-root"));
