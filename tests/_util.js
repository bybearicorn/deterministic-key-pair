export function test(name, fn) {
  try {
    fn();
    console.log(`ok - ${name}`);
  } catch (e) {
    console.error(`FAIL - ${name}`);
    console.error(e?.stack || e);
    process.exitCode = 1;
  }
}

export function validate() {
  if (!process.exitCode) {
    console.log("All tests passed.");
  } else {
    console.error("Some tests failed.");
  }
}
