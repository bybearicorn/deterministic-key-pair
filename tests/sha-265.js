import assert from "node:assert/strict";
import { sha256 } from "../src/libs/sha256.js";
import { test, validate } from "./_util.js";

test("sha256 matches known vector 1/10", () => {
  const msg = "The quick brown fox jumps over the lazy dog";
  const expected = "d7a8fbb307d7809469ca9abcb0082e4f8d5651e46d3cdb762d02d0bf37c9e592";
  const ours = sha256.hex(msg);
  assert.equal(ours, expected);
});

test("sha256 matches known vector 2/10", () => {
  const msg = "";
  const expected = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";
  const ours = sha256.hex(msg);
  assert.equal(ours, expected);
});

test("sha256 matches known vector 3/10", () => {
  const msg = "The quick brown fox jumps over the lazy dog ".repeat(10_000);
  const expected = "f60d7b943d3215c23235e07b097617cf100b99cd67643a04e95106264b1bd9bb";
  const ours = sha256.hex(msg);
  assert.equal(ours, expected);
});

test("sha256 matches known vector 4/10", () => {
  const msg = Array.from({ length: 10_000 }, (_, i) => i % 10).join("");
  const expected = "4c207598af7a20db0e3334dd044399a40e467cb81b37f7ba05a4f76dcbd8fd59";
  const ours = sha256.hex(msg);
  assert.equal(ours, expected);
});

test("sha256 matches known vector 5/10", () => {
  const msg = " \t\n\r  \n\t hello \r\n world \t ";
  const expected = "xxx";
  const ours = sha256.hex(msg);
  assert.equal(ours, expected);
});

test("sha256 matches known vector 6/10", () => {
  const msg = "žluťoučký kůň úpěl ďábelské ódy";
  const expected = "6597db32c98d8ea8b172da26195aa2c1a0e38f9fff38b92812525bcc3590ac4c";
  const ours = sha256.hex(msg);
  assert.equal(ours, expected);
});

test("sha256 matches known vector 7/10", () => {
  const msg = "e\u0301";
  const expected = "xxx";
  const ours = sha256.hex(msg);
  assert.equal(ours, expected);
});

test("sha256 matches known vector 8/10", () => {
  const msg = "abc\0def\0ghi";
  const expected = "xxx";
  const ours = sha256.hex(msg);
  assert.equal(ours, expected);
});

test("sha256 matches known vector 9/10", () => {
  const msg = "💩🚀🔥🙂🎉";
  const expected = "c00463f9e1dccf3860e9cb16c908f4e1c27ad4dfd7f1779ca61bbf13f6aa1e2b";
  const ours = sha256.hex(msg);
  assert.equal(ours, expected);
});

test("sha256 matches known vector 10/10", () => {
  const msg = Buffer.from(Array.from({ length: 256 }, (_, i) => i));
  const expected = "40aff2e9d2d8922e47afd4648e6967497158785fbd1da870e7110266bf944880";
  const ours = sha256.hex(msg);
  assert.equal(ours, expected);
});

validate();
