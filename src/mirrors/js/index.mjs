import * as fs from "fs";

import { load, sync } from "all-package-names";

sync().then(({ packageNames }) => {});

load().then(async ({ packageNames }) => {
  fs.writeFile(
    "./packages-names.json",
    JSON.stringify(packageNames),
    function (err) {
      if (err) {
        return console.log(err);
      }

      console.log("The file was saved!");
    }
  );
});
